rule sig_20160510_839821b10ebabff4fc937ec12985e0cf {
  meta:
    description = "datamaliciousorder - file 20160510_839821b10ebabff4fc937ec12985e0cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbd51c4af4b17d9b7d74b811cc06a0e10b1f8bbbc18b615562dbd51d160b92a2"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b X(3g,3h){if(\"\\\\i\\\\k\\\\r\\\\i\\\\P\\\\B" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}