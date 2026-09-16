rule sig_20160510_ebf9c5252da6f58be46c1962592be297 {
  meta:
    description = "datamaliciousorder - file 20160510_ebf9c5252da6f58be46c1962592be297.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5630385c600a2ac60c45b7ca36565ab6b376e799cea0dd0bc5a6b63f382bc74e"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d x(Y,13){4 a=0;if(5.m(a)===0){4 9z=\"9A\"}if(7(-9" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}