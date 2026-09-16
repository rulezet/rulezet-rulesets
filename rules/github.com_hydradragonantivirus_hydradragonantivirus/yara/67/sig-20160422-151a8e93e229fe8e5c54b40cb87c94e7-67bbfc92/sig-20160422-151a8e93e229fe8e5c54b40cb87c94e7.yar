rule sig_20160422_151a8e93e229fe8e5c54b40cb87c94e7 {
  meta:
    description = "datamaliciousorder - file 20160422_151a8e93e229fe8e5c54b40cb87c94e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f4879605903ce7a07f821e74ed66af20e001753b043e5043a3c7f93149abfb9"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('w 5m(5g,5j){g(1){b 1:8 8F=f;9;b 51:8 5l=8G;c(5l===" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}