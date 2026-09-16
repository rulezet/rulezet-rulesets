rule sig_20151216_8547af26c3d1e4768ac7f41dcfc7624b {
  meta:
    description = "datamaliciousorder - file 20151216_8547af26c3d1e4768ac7f41dcfc7624b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca4fb560a356c4bdc5ede8c15a618781cdb7a6b23782602900e304c797651c41"

  strings:
    $s1  = ".pow(Math.cos(803), 2) - 1)));} CjsrUofYu[riJbOCOEJqx]++;}riJbOCOEJqx++;} return yddtFHgeJxs}" fullword ascii
    $s2  = ") - 1));while(true){if (riJbOCOEJqx >= (4279+131)/735){break;}CjsrUofYu[riJbOCOEJqx]=Math.round((Math.pow(Math.sin(544), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(544), 2) - 1)); while(true) { if(CjsrUofYu[riJbOCOEJqx] > fZRJV[riJbOCOEJqx].length-(-525+869)/344) { break; } i" ascii
    $s4  = "function YBNBqaIMwhdnkkqmQ(fZRJV){yddtFHgeJxs= '';riJbOCOEJqx=Math.round((Math.pow(Math.sin(204), 2) + Math.pow(Math.cos(204), 2" ascii
    $s5  = "function YBNBqaIMwhdnkkqmQ(fZRJV){yddtFHgeJxs= '';riJbOCOEJqx=Math.round((Math.pow(Math.sin(204), 2) + Math.pow(Math.cos(204), 2" ascii
    $s6  = "TTrvyfzdmkXvxvlSLJbPAvkKJsjWPraNoRPE([fZRJV[riJbOCOEJqx][CjsrUofYu[riJbOCOEJqx]]], Math.round((Math.pow(Math.sin(803), 2) + Math" ascii
    $s7  = "function G(FgHFvUalQTpbNS,JKggWsfTNGGmT,ZAFUKYVozsW) {FgHFvUalQTpbNS[JKggWsfTNGGmT]=ZAFUKYVozsW;}" fullword ascii
    $s8  = "function TiWvZrYfDKdHyqY(iETcxZRvBLrAuQGRO,cXOxLiFQTNunMvyItjmhajEfkgmGWdAJkm,GfqnPDmyayQJzoPdIZLlHgPYRoBiiehvUHg){eval(iETcxZRv" ascii
    $s9  = "function srUVIngindfUHTFchlTTrvyfzdmkXvxvlSLJbPAvkKJsjWPraNoRPE(pIaRQbBQwDPqH,lwoxBRvDWIGhGz){ return xZlmePp[ZDNzdfif[XgWKs(pIa" ascii
    $s10 = "function XgWKs(QXxngFyNdQA,IqzcwMFqWAONU,fjneHJJE){amJP=GphNbIAeoVJGCKrMh(QXxngFyNdQA,IqzcwMFqWAONU);ZhUgv=amJP.toString(fjneHJJ" ascii
    $s11 = "E);return ZhUgv;}" fullword ascii
    $s12 = "function TiWvZrYfDKdHyqY(iETcxZRvBLrAuQGRO,cXOxLiFQTNunMvyItjmhajEfkgmGWdAJkm,GfqnPDmyayQJzoPdIZLlHgPYRoBiiehvUHg){eval(iETcxZRv" ascii
    $s13 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s14 = "function srUVIngindfUHTFchlTTrvyfzdmkXvxvlSLJbPAvkKJsjWPraNoRPE(pIaRQbBQwDPqH,lwoxBRvDWIGhGz){ return xZlmePp[ZDNzdfif[XgWKs(pIa" ascii
    $s15 = "function GphNbIAeoVJGCKrMh(PYEWpyJbQO,XZBJxzzTbs) {return parseInt(PYEWpyJbQO,XZBJxzzTbs);}" fullword ascii
    $s16 = "function H(kQYjCltLRCWz,rjZZIYqHNHGuOo){kQYjCltLRCWz.push(rjZZIYqHNHGuOo);}" fullword ascii
    $s17 = "function XgWKs(QXxngFyNdQA,IqzcwMFqWAONU,fjneHJJE){amJP=GphNbIAeoVJGCKrMh(QXxngFyNdQA,IqzcwMFqWAONU);ZhUgv=amJP.toString(fjneHJJ" ascii
    $s18 = "function ztUxExcvDYWryEk(RzusSYyGPnXNjpLrjjv) {return parseFloat(RzusSYyGPnXNjpLrjjv);}" fullword ascii
    $s19 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s20 = "function sxczHRjnfajb(aNAaqsUSymIsv) {return isFinite(aNAaqsUSymIsv);}" fullword ascii

  condition:
    uint16(0) == 0x445a and
    8 of them
}