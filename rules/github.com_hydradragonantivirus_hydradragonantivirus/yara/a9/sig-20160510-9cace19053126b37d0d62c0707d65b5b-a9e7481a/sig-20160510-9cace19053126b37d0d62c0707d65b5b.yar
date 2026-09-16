rule sig_20160510_9cace19053126b37d0d62c0707d65b5b {
  meta:
    description = "datamaliciousorder - file 20160510_9cace19053126b37d0d62c0707d65b5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a3913d15f0056d4eec984a26715d6975d8e1032c879c8307c51da4a221e1d1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 9P(x,H){4 S=1;if(5.o(S)>0){9Q=\\'-9O\\'}6{4 9N=9" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}