rule sig_20160510_7b0c51197442a0a67745a5416d66b133 {
  meta:
    description = "datamaliciousorder - file 20160510_7b0c51197442a0a67745a5416d66b133.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07299db2425acc7e7db862e3af91f892758b8199a0b4c8b9aac865f66bd95617"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('9 1t(){13{4 6T=f}14(6V){4 hI=7f}1m{7i=7(-7k)}if(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}