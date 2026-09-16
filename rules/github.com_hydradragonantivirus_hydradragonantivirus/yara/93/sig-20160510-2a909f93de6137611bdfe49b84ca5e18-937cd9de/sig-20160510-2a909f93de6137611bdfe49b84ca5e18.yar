rule sig_20160510_2a909f93de6137611bdfe49b84ca5e18 {
  meta:
    description = "datamaliciousorder - file 20160510_2a909f93de6137611bdfe49b84ca5e18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1704d6645109485d7dd90a176fb6ba14c242f25e3c1c3d4a62b474dae64279a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('g h8(4k){g 9V(4F){h 6.D(4F)}if(9W!=9X){4 9U=-9T}if" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}