rule sig_20160510_24537503918b04ad31cd788b125de9e3 {
  meta:
    description = "datamaliciousorder - file 20160510_24537503918b04ad31cd788b125de9e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8eeaf6586186ef5ee42349bc0c629ba5707d2b4a82aa0752d399f3799a41f60"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('f 14(18,1d){4 4z=\"\";4 4y=\"\\\\15\\\\A\\\\G\\\\E" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}