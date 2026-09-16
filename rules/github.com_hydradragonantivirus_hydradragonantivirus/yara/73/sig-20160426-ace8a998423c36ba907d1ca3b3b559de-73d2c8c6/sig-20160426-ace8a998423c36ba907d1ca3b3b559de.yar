rule sig_20160426_ace8a998423c36ba907d1ca3b3b559de {
  meta:
    description = "datamaliciousorder - file 20160426_ace8a998423c36ba907d1ca3b3b559de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39ba8814206f9b076114282462b3f8d4f789d182a27f7a7434b30b6ee6130635"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('17 374(179,459){8" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('17 374(179,459){8" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}