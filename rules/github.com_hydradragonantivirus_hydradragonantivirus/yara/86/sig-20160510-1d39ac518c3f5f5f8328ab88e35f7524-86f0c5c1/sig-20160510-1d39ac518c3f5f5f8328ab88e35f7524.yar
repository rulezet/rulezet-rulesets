rule sig_20160510_1d39ac518c3f5f5f8328ab88e35f7524 {
  meta:
    description = "datamaliciousorder - file 20160510_1d39ac518c3f5f5f8328ab88e35f7524.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42d503eb89d1ae0423cd6222afd4e410a1e85f7119fc42533ca3f87aceb24149"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b X(15,j,10,1j){if(\"9A\".c>=7(-9B)){9z=9y}if(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}