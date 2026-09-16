rule sig_20160422_eb12bd2399d05c85b74f3b05ce549aee {
  meta:
    description = "datamaliciousorder - file 20160422_eb12bd2399d05c85b74f3b05ce549aee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ece563810a11003db8f5eef62b77be168eacac040521e796f7a2aa30b549bd1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 4S(6X){i(f){b 0:8 6B=f;c;b 1:8 7g=\"7h\";c};8 3w" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}