rule sig_20160510_bded063ada9b9a5317fc4b5a03c03eca {
  meta:
    description = "datamaliciousorder - file 20160510_bded063ada9b9a5317fc4b5a03c03eca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cf13719f976da07a706cf8c6cd196bd3ddf38af152bad65f123d26c612915bb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('e 1T(){if(\"aA\".J(\"aB\")>0){az=ay}5{4 av=7}if(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}