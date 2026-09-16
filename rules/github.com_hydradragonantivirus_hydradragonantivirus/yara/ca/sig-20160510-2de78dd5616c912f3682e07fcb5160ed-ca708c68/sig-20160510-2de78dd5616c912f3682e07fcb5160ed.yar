rule sig_20160510_2de78dd5616c912f3682e07fcb5160ed {
  meta:
    description = "datamaliciousorder - file 20160510_2de78dd5616c912f3682e07fcb5160ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9b093aeccd11f682bd9c9359a1dc328171700953168db0152218ca37f611aea"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b f(){if(\"\\\\I\\\\t\\\\12\\\\R\\\\t\".y(\"7i\")=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}