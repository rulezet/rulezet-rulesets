rule sig_20160510_917570bf9ed47ab1a8aad0d0d6c8306e {
  meta:
    description = "datamaliciousorder - file 20160510_917570bf9ed47ab1a8aad0d0d6c8306e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "802737e12ab18b17e092b910c348fa8e866a6defde74bcbeb6a5778fe089a839"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d 1l(4j){4 4D=-1;if(6.h(4D)>=0){4 at=b}5{7t=b}4 4R" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}