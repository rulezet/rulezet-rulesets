rule sig_20160422_51ab0b636c9d9ebcacae7edbe4380f48 {
  meta:
    description = "datamaliciousorder - file 20160422_51ab0b636c9d9ebcacae7edbe4380f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca768bcc6d87ebd5f10b043441afdf119ccc6bf79be7e366d2899847da43015c"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('n 51(7R,50,57){8 7Q=\"7P\";g(7S){9 0:c(57==83){8 2" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}