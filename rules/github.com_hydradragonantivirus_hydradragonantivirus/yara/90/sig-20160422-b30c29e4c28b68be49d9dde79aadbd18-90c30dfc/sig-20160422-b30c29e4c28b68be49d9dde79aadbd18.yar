rule sig_20160422_b30c29e4c28b68be49d9dde79aadbd18 {
  meta:
    description = "datamaliciousorder - file 20160422_b30c29e4c28b68be49d9dde79aadbd18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f97f01f527ee2393cbd63e345e16dc3671477a6403a0ef4786c76592bbbd3c1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 5R(6H){k(6M){c f:8 6l=\"7J\";9(6l===1){8 R=7C;R=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}