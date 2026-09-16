rule sig_20160510_da870fa31ededcc3079e80796706035a {
  meta:
    description = "datamaliciousorder - file 20160510_da870fa31ededcc3079e80796706035a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2afe2d7d48ddb7b9db800166b12a573e1a445883f2ca942ed10f4650f00818bd"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d 3T(1m,1c,c,1q){if(9(-9T)<=-9U){9V=\\'\\\\Q\\\\10" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}