rule sig_20160510_75ed7d17a62b8d0f16e193081c1a608e {
  meta:
    description = "datamaliciousorder - file 20160510_75ed7d17a62b8d0f16e193081c1a608e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41ebd0c6a3181c1b6eb71a82bcb4107561182da8d5bf9c0d3009c1001be5816e"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('e aE(k3,3h){4 H=1;if(6.K(H)>0){4 aF=\"aD\"}4 l=1;i" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}