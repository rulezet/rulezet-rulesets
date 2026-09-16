rule sig_20160421_a9b7303a274b3d5994d5a09ca5a64bc4 {
  meta:
    description = "datamaliciousorder - file 20160421_a9b7303a274b3d5994d5a09ca5a64bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d5c9a2b120bf757751a5203ce0b02e1579dbc29102cfdce8a15351ac4751531"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 3M(1D,5o,5n){8 4V=5p;8 16=4w;9(16==\"1\"){8 Q=4q" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}