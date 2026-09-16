rule sig_20160422_cda77877496070e742370dc6d3691787 {
  meta:
    description = "datamaliciousorder - file 20160422_cda77877496070e742370dc6d3691787.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a1be555bc1156ee62dcdb5145db765f93b2fb13861de5eb76905c4d46572c21"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 5o(8b,8a,8c){8 8d=8e}i 2E(2W){8 2T=89(2W);j 2T}i" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}