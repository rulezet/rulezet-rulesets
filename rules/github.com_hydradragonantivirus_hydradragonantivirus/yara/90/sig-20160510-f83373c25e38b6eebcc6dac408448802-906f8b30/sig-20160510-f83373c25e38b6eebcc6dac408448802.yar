rule sig_20160510_f83373c25e38b6eebcc6dac408448802 {
  meta:
    description = "datamaliciousorder - file 20160510_f83373c25e38b6eebcc6dac408448802.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d791adcf8529538a95e538d6b60aa6310b589d21e526862a8ae7a5e994cd086"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('a 1s(3m){a u(3X){g 5.I(3X)}4 3Z=1;if(5.I(3Z)>=0){f" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}