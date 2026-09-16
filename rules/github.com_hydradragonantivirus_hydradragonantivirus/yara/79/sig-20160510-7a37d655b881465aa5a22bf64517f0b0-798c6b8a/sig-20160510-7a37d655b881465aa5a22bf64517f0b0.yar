rule sig_20160510_7a37d655b881465aa5a22bf64517f0b0 {
  meta:
    description = "datamaliciousorder - file 20160510_7a37d655b881465aa5a22bf64517f0b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be3e556e9a43f0887457f5f67dfc284ac9d94aa1d59a942f81890d533350f9b8"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 1R(17,11,l,1n){4 je=0;if(5.W(je)!=0){a5=\"9L\"}4" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}