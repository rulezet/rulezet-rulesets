rule sig_20160510_0d29013503f705a253318ecba66e3ea1 {
  meta:
    description = "datamaliciousorder - file 20160510_0d29013503f705a253318ecba66e3ea1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68b822017087cc33e12187c136a4ee8b1cbfc9912c4638d16cfbfa24974f6fdb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('g N(4k){if(\"98\".M(\"99\")==-1){97=\\'95\\'}4 4d=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}