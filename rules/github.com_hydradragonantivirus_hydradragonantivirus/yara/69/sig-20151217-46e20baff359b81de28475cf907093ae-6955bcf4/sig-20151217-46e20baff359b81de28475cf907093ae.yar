rule sig_20151217_46e20baff359b81de28475cf907093ae {
  meta:
    description = "datamaliciousorder - file 20151217_46e20baff359b81de28475cf907093ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89638db857788baa04b677538b43c65052d1906a9bf0935334358c14ed6704ad"

  strings:
    $s1  = "pow(Math.cos(999), 2) - 1)));} SKXMuRJUv[pjdDyuKnEAV]++;}pjdDyuKnEAV++;} return MMxhPytzHtJ}" fullword ascii
    $s2  = "function ELQIvTvgVXRlusjXs(ZVYUQ){MMxhPytzHtJ= '';pjdDyuKnEAV=Math.round((Math.pow(Math.sin(875), 2) + Math.pow(Math.cos(875), 2" ascii
    $s3  = "h.pow(Math.cos(502), 2) - 1)); while(true) { if(SKXMuRJUv[pjdDyuKnEAV] > ZVYUQ[pjdDyuKnEAV].length-(-213+375)/162) { break; } if" ascii
    $s4  = ") - 1));while(true){if (pjdDyuKnEAV >= (-342+804)/77){break;}SKXMuRJUv[pjdDyuKnEAV]=Math.round((Math.pow(Math.sin(502), 2) + Mat" ascii
    $s5  = "JvjANVMpcKCKbZanyOoknhlBifjOzwCmIHt([ZVYUQ[pjdDyuKnEAV][SKXMuRJUv[pjdDyuKnEAV]]], Math.round((Math.pow(Math.sin(999), 2) + Math." ascii
    $s6  = "function ELQIvTvgVXRlusjXs(ZVYUQ){MMxhPytzHtJ= '';pjdDyuKnEAV=Math.round((Math.pow(Math.sin(875), 2) + Math.pow(Math.cos(875), 2" ascii
    $s7  = "function sRAQtdT(vRkpobIbydLiRtqDwMRXiBwJTzqUzgHWhNda) {return !PVEWyGiORYR(cEQamwOpQqNkFTe(vRkpobIbydLiRtqDwMRXiBwJTzqUzgHWhNda" ascii
    $s8  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s9  = "function jCRRS(RSwqpvVCNwV,buoppWATzApLS,UZKomdxH){RpEq=hfsTNXkGNJFKLVZoY(RSwqpvVCNwV,buoppWATzApLS);jffsO=RpEq.toString(UZKomdx" ascii
    $s10 = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s11 = "function phUYbJifwqfLsRedMWbJvjANVMpcKCKbZanyOoknhlBifjOzwCmIHt(SRIeXZxkuHdAX,KsbimbApmEBSDJ){ return qLQdBvH[mmXSnqPW[jCRRS(SRI" ascii
    $s12 = "function jCRRS(RSwqpvVCNwV,buoppWATzApLS,UZKomdxH){RpEq=hfsTNXkGNJFKLVZoY(RSwqpvVCNwV,buoppWATzApLS);jffsO=RpEq.toString(UZKomdx" ascii
    $s13 = "function ehMiDUHiTdNu(wXjNQoKxrkBPH) {return isFinite(wXjNQoKxrkBPH);}" fullword ascii
    $s14 = "function A(GicMbGDCqVim,zWEhVuEJYjWITZ){GicMbGDCqVim.push(zWEhVuEJYjWITZ);}" fullword ascii
    $s15 = "H);return jffsO;}" fullword ascii
    $s16 = "function hfsTNXkGNJFKLVZoY(lZtzLHPWHC,EQFOnOGgae) {return parseInt(lZtzLHPWHC,EQFOnOGgae);}" fullword ascii
    $s17 = "function PVEWyGiORYR(lyXdZWFJkNNmdw) {return isNaN(lyXdZWFJkNNmdw);}" fullword ascii
    $s18 = "function phUYbJifwqfLsRedMWbJvjANVMpcKCKbZanyOoknhlBifjOzwCmIHt(SRIeXZxkuHdAX,KsbimbApmEBSDJ){ return qLQdBvH[mmXSnqPW[jCRRS(SRI" ascii
    $s19 = "function srFmADinGpNYLvb(wSUNhBUmuObrlukIS,AkLtcmaWUrvnGWFIdADfUxmqrxfLzEwwIT,zGHyYJdCkDknEWYuNFfIHbvhyqVsAXnfxgp){eval(wSUNhBUm" ascii
    $s20 = "function sRAQtdT(vRkpobIbydLiRtqDwMRXiBwJTzqUzgHWhNda) {return !PVEWyGiORYR(cEQamwOpQqNkFTe(vRkpobIbydLiRtqDwMRXiBwJTzqUzgHWhNda" ascii

  condition:
    uint16(0) == 0x6d6d and
    8 of them
}