rule sig_20160421_f87ba89986dae672320efb23717c2ea4 {
  meta:
    description = "datamaliciousorder - file 20160421_f87ba89986dae672320efb23717c2ea4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2983c98a859809523a00eb0e2f7826556a0360852681b58e3eea533291e2c57c"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 33(3x,4s,4r,4t){8 4u=\"4w\";8 4q=4p;i(3x){9 e:8 " ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}