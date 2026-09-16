rule sig_20160510_60efaf4124df06a4963b23ce45317782 {
  meta:
    description = "datamaliciousorder - file 20160510_60efaf4124df06a4963b23ce45317782.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e11ae61b0adc83c254f7129a22fb162ad089179c08913eed5870cf8816c21013"

  strings:
    $x1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c x(19,13,l,1h){c je(db){g 5.1p(db)}4 3U=0;if(5.o(" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and all of them
}