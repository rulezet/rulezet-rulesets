rule sig_20160510_60c646efc724f960de14b1d4183e6441 {
  meta:
    description = "datamaliciousorder - file 20160510_60c646efc724f960de14b1d4183e6441.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef2262202005046f919cd60275bb450bda58132647601a248a9a5e77d0f46836"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('g 4c(){4 4D=0;if(6.y(4D)>=0){4 N=-gp}4 f=\"gR\";if" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}