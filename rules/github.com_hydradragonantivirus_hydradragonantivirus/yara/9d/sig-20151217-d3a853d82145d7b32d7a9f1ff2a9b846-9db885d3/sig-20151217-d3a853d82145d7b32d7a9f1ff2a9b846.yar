rule sig_20151217_d3a853d82145d7b32d7a9f1ff2a9b846 {
  meta:
    description = "datamaliciousorder - file 20151217_d3a853d82145d7b32d7a9f1ff2a9b846.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4abb007ca9fb11b39cd14a6b55c0b0452885965cf62a4973a78ed800839245c"

  strings:
    $s1  = "w(Math.cos(45), 2) - 1)));} AvodmpGBP[nldQBaWKtig]++;}nldQBaWKtig++;} return kjQINkLclPS}" fullword ascii
    $s2  = ") - 1));while(true){if (nldQBaWKtig >= (208+992)/200){break;}AvodmpGBP[nldQBaWKtig]=Math.round((Math.pow(Math.sin(894), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(894), 2) - 1)); while(true) { if(AvodmpGBP[nldQBaWKtig] > cVZYs[nldQBaWKtig].length-(366+256)/622) { break; } if " ascii
    $s4  = "function ZJUzzWDKshsQRYUVS(cVZYs){kjQINkLclPS= '';nldQBaWKtig=Math.round((Math.pow(Math.sin(105), 2) + Math.pow(Math.cos(105), 2" ascii
    $s5  = "function ZJUzzWDKshsQRYUVS(cVZYs){kjQINkLclPS= '';nldQBaWKtig=Math.round((Math.pow(Math.sin(105), 2) + Math.pow(Math.cos(105), 2" ascii
    $s6  = "function FPytitz(JqIOpqMgWgxtXeTDNjPHtOKzfPzYyKFpEjFY) {return !LvwVcnSMUkP(UwQoqfcFQcGJBIL(JqIOpqMgWgxtXeTDNjPHtOKzfPzYyKFpEjFY" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "function UwQoqfcFQcGJBIL(SqPlKcpLOqTYxbaedpE) {return parseFloat(SqPlKcpLOqTYxbaedpE);}" fullword ascii
    $s9  = "function j(ylhuHEBzfAeVWf,YNzRWYpHiqvSG,xMCbjxgyhRi) {ylhuHEBzfAeVWf[YNzRWYpHiqvSG]=xMCbjxgyhRi;}" fullword ascii
    $s10 = "function FPytitz(JqIOpqMgWgxtXeTDNjPHtOKzfPzYyKFpEjFY) {return !LvwVcnSMUkP(UwQoqfcFQcGJBIL(JqIOpqMgWgxtXeTDNjPHtOKzfPzYyKFpEjFY" ascii
    $s11 = "q);return noaxS;}" fullword ascii
    $s12 = "function JmmfD(PHrLQyeltMs,tBKcWuJyjuDJx,DcLrkCTq){mvNU=ddDRHTgASvTSmLUeR(PHrLQyeltMs,tBKcWuJyjuDJx);noaxS=mvNU.toString(DcLrkCT" ascii
    $s13 = "function AcqLErZVeYGdKjT(CLJOYFnzSwvkFQmJn,wpnpDAEmyNqGoXRcruErqQfUoTKifCKIvI,jxroLwIKGlLexzGNsaJJWLcxlMirGAPvYuY){eval(CLJOYFnz" ascii
    $s14 = "function JmmfD(PHrLQyeltMs,tBKcWuJyjuDJx,DcLrkCTq){mvNU=ddDRHTgASvTSmLUeR(PHrLQyeltMs,tBKcWuJyjuDJx);noaxS=mvNU.toString(DcLrkCT" ascii
    $s15 = "function J(xesoUyCLkHqi,YvBdVIOfirpATA){xesoUyCLkHqi.push(YvBdVIOfirpATA);}" fullword ascii
    $s16 = "function XGScMsbSERbHcnLylCLUFWhsTqFMrocoYoFltmMvBExegDCyIQHIcU(kMLYcoEEyfaUB,SgqKoTlOxuJrJN){ return cvFZkuO[cuqFxGef[JmmfD(kML" ascii
    $s17 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s18 = "function ddDRHTgASvTSmLUeR(ITrIGncEla,mDRBnypZQr) {return parseInt(ITrIGncEla,mDRBnypZQr);}" fullword ascii
    $s19 = "function FozwRMOYhcBp(AtZDGPfPMkQWw) {return isFinite(AtZDGPfPMkQWw);}" fullword ascii
    $s20 = "function AcqLErZVeYGdKjT(CLJOYFnzSwvkFQmJn,wpnpDAEmyNqGoXRcruErqQfUoTKifCKIvI,jxroLwIKGlLexzGNsaJJWLcxlMirGAPvYuY){eval(CLJOYFnz" ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}