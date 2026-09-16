rule sig_20160421_85b9aebfcefbe2df523c66cbc27ebc89 {
  meta:
    description = "datamaliciousorder - file 20160421_85b9aebfcefbe2df523c66cbc27ebc89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f526e1bb5e754cf0a686a0a7c4091eced7828d510e78088a18f93a63ff16c1e1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 45(60,61,62){8 5Z=\"5Y\";k 0}j 3j(26){8 2e=5U(26" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}