rule sig_20160510_b9b01935c4c16b862a38b6d607e0864e {
  meta:
    description = "datamaliciousorder - file 20160510_b9b01935c4c16b862a38b6d607e0864e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af2e65b84c7f3de798898ce7ec90671142c69007949f52f10ee21e3ac52bd3b7"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 2j(q,V,I,1i){if(\"-ap\"!=\"-aq\"){X=\"-ao\"}6{an" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}