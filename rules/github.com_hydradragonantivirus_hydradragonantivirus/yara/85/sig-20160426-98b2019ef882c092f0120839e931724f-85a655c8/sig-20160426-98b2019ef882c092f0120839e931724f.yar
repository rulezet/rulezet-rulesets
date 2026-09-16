rule sig_20160426_98b2019ef882c092f0120839e931724f {
  meta:
    description = "datamaliciousorder - file 20160426_98b2019ef882c092f0120839e931724f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79d0667ffaac13058132e6ec4a06aeeaeb03f0959a424629d339f264df69afb2"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('14 430(412,487,44" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('14 430(412,487,44" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}