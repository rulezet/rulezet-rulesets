rule sig_20160422_264635642686d653da1ee9d92c91c13b {
  meta:
    description = "datamaliciousorder - file 20160422_264635642686d653da1ee9d92c91c13b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "767ddfe151ed60470267136771302b623416739deee91fe7bade64a1f8ea81d2"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 3m(7p){6 6h=7n;b(6h===\"7v\"){6 65=c;b(65===\"76" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}