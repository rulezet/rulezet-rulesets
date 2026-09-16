rule sig_20160510_e96091b1939530c8b51df1d2e6eacaff {
  meta:
    description = "datamaliciousorder - file 20160510_e96091b1939530c8b51df1d2e6eacaff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f20658b7e03aa6341b92616edd5c3cbaaf65fb97521cb5acc4440631018988"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 11(12,g){if(9n!=9o){4 9m=9}6{9l=d}if(\"9i\".G(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}