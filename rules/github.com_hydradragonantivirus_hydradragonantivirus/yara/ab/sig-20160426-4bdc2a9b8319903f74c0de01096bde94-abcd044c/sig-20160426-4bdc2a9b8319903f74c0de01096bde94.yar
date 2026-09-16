rule sig_20160426_4bdc2a9b8319903f74c0de01096bde94 {
  meta:
    description = "datamaliciousorder - file 20160426_4bdc2a9b8319903f74c0de01096bde94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a22988c2ddfd6e79c2f7ec3f41664b177058c9559de0a7cf5f36541b4a4934b"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('18 317(171,175){8" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('18 317(171,175){8" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}