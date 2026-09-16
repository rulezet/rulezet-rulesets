rule sig_20160512_e8b58c723f46889e7f12e3d8a6a45d14 {
  meta:
    description = "datamaliciousorder - file 20160512_e8b58c723f46889e7f12e3d8a6a45d14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27cfbb58a0493d76ba3f8a7b202ad81b83e605832d4fb8f356c00e3f093d4a02"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 2A(){3 17=\"f\";5 17}4 w(){3 2z=\"r\";5 2z}4 I()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}