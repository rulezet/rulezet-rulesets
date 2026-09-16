rule sig_20160510_92be839e93764cf7351f46ac6138aeb3 {
  meta:
    description = "datamaliciousorder - file 20160510_92be839e93764cf7351f46ac6138aeb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1daaf8dfa4d19a8f07910eca68b67580ba0d2ec5b96c0ee7411b5f37976f94bd"

  strings:
    $x1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('f 2a(){if(\"9U\".Y(\"9V\")<0){4 9T=9}4 2i=-1;if(5." ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and all of them
}