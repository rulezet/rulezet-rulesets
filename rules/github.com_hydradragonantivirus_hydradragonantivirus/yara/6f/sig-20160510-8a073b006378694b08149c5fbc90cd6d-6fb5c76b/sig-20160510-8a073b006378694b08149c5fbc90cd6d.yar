rule sig_20160510_8a073b006378694b08149c5fbc90cd6d {
  meta:
    description = "datamaliciousorder - file 20160510_8a073b006378694b08149c5fbc90cd6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ab02520a4d7b3895c7bfdb89d39805c5d3ac7461d2d3595e4e6bf7be6e14c10"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('f O(I,1d){if(\"9F\".15(\"\")==0){4 p=9G}if(\"9E\"!" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}