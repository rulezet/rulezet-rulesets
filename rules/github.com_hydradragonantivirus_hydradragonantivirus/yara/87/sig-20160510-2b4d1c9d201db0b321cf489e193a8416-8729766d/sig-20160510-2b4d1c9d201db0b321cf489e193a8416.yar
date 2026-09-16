rule sig_20160510_2b4d1c9d201db0b321cf489e193a8416 {
  meta:
    description = "datamaliciousorder - file 20160510_2b4d1c9d201db0b321cf489e193a8416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2634af12c73f805deefd27b3ceb62b3f5886dcf9b52a690078d587e827d2fddb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d V(E,B){4 4n=1;if(5.Q(4n)===0){eg=\"\"}6{4 hC=\\'" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}