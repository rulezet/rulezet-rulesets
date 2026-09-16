rule sig_20160421_5c64b286bf34b7948158d4c5ebd89125 {
  meta:
    description = "datamaliciousorder - file 20160421_5c64b286bf34b7948158d4c5ebd89125.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c223787fae794dd19d53fb7a370d5f111f3a9072802f08acc052a38a510845b4"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 3I(6a,68,4x,6g){8 5m=6f;c(5m==65){8 5Y=e}8 4E=\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}