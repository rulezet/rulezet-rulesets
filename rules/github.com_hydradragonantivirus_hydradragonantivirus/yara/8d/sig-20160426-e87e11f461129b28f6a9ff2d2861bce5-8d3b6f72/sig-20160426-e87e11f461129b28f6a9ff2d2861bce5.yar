rule sig_20160426_e87e11f461129b28f6a9ff2d2861bce5 {
  meta:
    description = "datamaliciousorder - file 20160426_e87e11f461129b28f6a9ff2d2861bce5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f18a2db7c6321d7706b132ff0b9dde647b9834236c5ef09c14d51de912f02da9"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('19 348(449,448){8" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('19 348(449,448){8" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}