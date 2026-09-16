rule sig_20160512_e44a9939f1900ce763b0c4f7f3e48cfe {
  meta:
    description = "datamaliciousorder - file 20160512_e44a9939f1900ce763b0c4f7f3e48cfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ce6c00a4435e4935cb59a0f83f6e95493b01bedd39079935bc09a65587f1ae2"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 2f(){3 1R=\"f\";5 1R}4 w(){3 1Q=\"r\";5 1Q}4 D()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}