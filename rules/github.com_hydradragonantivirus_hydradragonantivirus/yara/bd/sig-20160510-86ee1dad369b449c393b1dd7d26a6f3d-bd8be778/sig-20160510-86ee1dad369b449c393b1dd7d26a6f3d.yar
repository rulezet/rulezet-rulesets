rule sig_20160510_86ee1dad369b449c393b1dd7d26a6f3d {
  meta:
    description = "datamaliciousorder - file 20160510_86ee1dad369b449c393b1dd7d26a6f3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "993b891003eec8ab2dd78e35b28179d521d6172ac7047be7c868047a1c9dcef6"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('a 22(){4 4J=1;if(5.X(4J)==0){4 76=6X}if(\"71\".H(" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}