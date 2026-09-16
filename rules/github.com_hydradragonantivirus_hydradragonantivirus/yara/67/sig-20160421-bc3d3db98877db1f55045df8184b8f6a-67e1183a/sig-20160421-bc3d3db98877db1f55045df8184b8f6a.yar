rule sig_20160421_bc3d3db98877db1f55045df8184b8f6a {
  meta:
    description = "datamaliciousorder - file 20160421_bc3d3db98877db1f55045df8184b8f6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89fd1360730a512b807bd5b89e9f5ae5c3f3e8a962b84482ea2b1930ca9d7bfb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 30(l,t,w){g(l){b 7x:8 8W=\"7v\";9;b\"0\":c(w==\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}