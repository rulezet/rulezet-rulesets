rule sig_20160510_43241eeb6a9da52e83786b888b2244e9 {
  meta:
    description = "datamaliciousorder - file 20160510_43241eeb6a9da52e83786b888b2244e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0073dbb4c1f65577563fdf68ddb2f7b6032a461bb837d8fc8a07fc2613dc575f"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 4m(F,15){if(\"7f\".v(\"-7h\")<0){77=\\'7b\\'}if(" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}