rule sig_20160512_6eb00d3714d088187898d2ddb39cdd97 {
  meta:
    description = "datamaliciousorder - file 20160512_6eb00d3714d088187898d2ddb39cdd97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "002b7d68cca07753cd5ccfa1bd752ec743cfcee37035b94379b3277192558fcc"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 1Z(){3 1A=\"f\";5 1A}4 n(){3 1z=\"r\";5 1z}4 G()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}