rule sig_20160510_e64afa5bd62569d30831d8f960aaa945 {
  meta:
    description = "datamaliciousorder - file 20160510_e64afa5bd62569d30831d8f960aaa945.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df838bb747619c95a1d4cfbc2fff7a1d505d20cf10cee292a09c1f18c3cbbc22"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d 3e(){if(\"\\\\v\\\\12\\\\19\\\\p\\\\H\\\\18\\\\L" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}