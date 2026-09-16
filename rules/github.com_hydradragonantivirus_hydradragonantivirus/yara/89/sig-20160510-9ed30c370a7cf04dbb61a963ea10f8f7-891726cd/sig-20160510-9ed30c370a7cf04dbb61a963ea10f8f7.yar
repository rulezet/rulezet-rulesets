rule sig_20160510_9ed30c370a7cf04dbb61a963ea10f8f7 {
  meta:
    description = "datamaliciousorder - file 20160510_9ed30c370a7cf04dbb61a963ea10f8f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4156382f32372f0023f7bd583c7daa67251da85a04debfab828483d100a6ae43"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('e 27(Y,hx){if(\"7f\".d>7j){4 7i=7c}6{e5=7b}if(\"7u" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}