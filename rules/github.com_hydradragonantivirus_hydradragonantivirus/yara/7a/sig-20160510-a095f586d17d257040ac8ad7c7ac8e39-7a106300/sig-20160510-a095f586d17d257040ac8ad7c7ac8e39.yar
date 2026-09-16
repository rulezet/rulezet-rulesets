rule sig_20160510_a095f586d17d257040ac8ad7c7ac8e39 {
  meta:
    description = "datamaliciousorder - file 20160510_a095f586d17d257040ac8ad7c7ac8e39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "302a539a194252ccae7d95f6b3ce57c3755a1153cfa5e4fd74ddd90df9a58d3b"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('a k(4c){4 4J=0;if(6.u(4J)==0){4 5N=\\'-6q\\'}5{4 6" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}