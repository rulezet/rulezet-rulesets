rule sig_20160421_433c763931e3ddaac97b6a392c4685b1 {
  meta:
    description = "datamaliciousorder - file 20160421_433c763931e3ddaac97b6a392c4685b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d31100554de59bfc64d12598b75538b661cde9b1321f4f0ba564d9d6ad421e17"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('k 3O(4P){8 4D=f;9(4D===f){8 1T=4V;8 4u=u;8 4K=51;1" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}