rule sig_20160422_9f7a1e545611eb56637d612280e9ea37 {
  meta:
    description = "datamaliciousorder - file 20160422_9f7a1e545611eb56637d612280e9ea37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c48ef0ff917921137d94620e10400826b55a1f06be638f6ac42390b52e63fc4"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('l 6r(2v,7h,2R,7i){e(2R==g){9 7K=\"7R\"}h(2v){c g:e" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}