rule sig_20160421_ed46b9f2bd0753ae22dcec19db7d290b {
  meta:
    description = "datamaliciousorder - file 20160421_ed46b9f2bd0753ae22dcec19db7d290b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "398720dbafa1adcd3f787d0bb91bd05968b62fa2e5e514bec1631a0e12704d2d"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 1z(){8 2k=\"4L\";9(2k===\"0\"){8 6h=b;8 6a=\"5B" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}