rule sig_20160426_2fd7c23a863852c2e04fa7fa3f0c2f03 {
  meta:
    description = "datamaliciousorder - file 20160426_2fd7c23a863852c2e04fa7fa3f0c2f03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43b9084201e889e1f4f4d830db8c7bf8683d0eecdf6002170ccdefc85497f7a1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('14 424(32,468){11" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('14 424(32,468){11" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}