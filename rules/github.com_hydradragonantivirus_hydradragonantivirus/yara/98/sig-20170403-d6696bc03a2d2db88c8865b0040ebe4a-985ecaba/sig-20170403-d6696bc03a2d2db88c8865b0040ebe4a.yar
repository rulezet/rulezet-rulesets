rule sig_20170403_d6696bc03a2d2db88c8865b0040ebe4a {
  meta:
    description = "datamaliciousorder - file 20170403_d6696bc03a2d2db88c8865b0040ebe4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faad4f8730db9825cfc5fd29f105a16849c83e61e836d68b2e3eff55fe0f1ec5"

  strings:
    $x1 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e" ascii
    $s2 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e" ascii
    $s3 = "]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('1 6" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and all of them
}