rule sig_20151217_0f601bdc5d66c2d30f55dc2bc7047610 {
  meta:
    description = "datamaliciousorder - file 20151217_0f601bdc5d66c2d30f55dc2bc7047610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cb61093d9d0acdca639f632b1c85f83e198d3e76a5d7eb0d572d94bfe7e1b6c"

  strings:
    $s1  = "function tqFCVlJxknAKXBcyV(Xaxli){dezRlvOKzun= '';doyWvoCfvWp=Math.round((Math.pow(Math.sin(79), 2) + Math.pow(Math.cos(79), 2) " ascii
    $s2  = ".pow(Math.cos(445), 2) - 1)); while(true) { if(mlBSBCvnw[doyWvoCfvWp] > Xaxli[doyWvoCfvWp].length-(-312+754)/442) { break; } if " ascii
    $s3  = "w(Math.cos(275), 2) - 1)));} mlBSBCvnw[doyWvoCfvWp]++;}doyWvoCfvWp++;} return dezRlvOKzun}" fullword ascii
    $s4  = "function tqFCVlJxknAKXBcyV(Xaxli){dezRlvOKzun= '';doyWvoCfvWp=Math.round((Math.pow(Math.sin(79), 2) + Math.pow(Math.cos(79), 2) " ascii
    $s5  = "- 1));while(true){if (doyWvoCfvWp >= (4295+223)/753){break;}mlBSBCvnw[doyWvoCfvWp]=Math.round((Math.pow(Math.sin(445), 2) + Math" ascii
    $s6  = "function ZFwSMOt(xPyORxZFABBpuCXbwPmjdXaXDpFFnTmLLQXf) {return !BZgPdvoKtYd(djBZefIoNtWaqPH(xPyORxZFABBpuCXbwPmjdXaXDpFFnTmLLQXf" ascii
    $s7  = "function ikIpMjwkKKxxKpATx(gguAAaolCT,nypZnMhDCe) {return parseInt(gguAAaolCT,nypZnMhDCe);}" fullword ascii
    $s8  = "function djBZefIoNtWaqPH(PGcUvbSnuuwBwyJFoxQ) {return parseFloat(PGcUvbSnuuwBwyJFoxQ);}" fullword ascii
    $s9  = "function h(SnJmLwpgNbCggD,OQOUpRrJcpspH,NMuYpMKZEXV) {SnJmLwpgNbCggD[OQOUpRrJcpspH]=NMuYpMKZEXV;}" fullword ascii
    $s10 = "p);return UWNYX;}" fullword ascii
    $s11 = "function PTdmxeEoKnLXKxvvYfGrcNFFiLWQzTAuLBbsEAixSdKLnOGDwjlEKM(gkPiUCMARIrrx,BfMdemuVLIzgor){ return nXwMWeT[levbmOjw[YGTOu(gkP" ascii
    $s12 = "function oGhJHqbbnChrPuS(lWGjCGJnnRmiFoJWY,GFGnhgOxMwOFxpOnavTrkxJvAyLHRBLHHl,gBIcjhQOOdQChRjPqpJzWmZRYVHGPExmpRH){eval(lWGjCGJn" ascii
    $s13 = "function PTdmxeEoKnLXKxvvYfGrcNFFiLWQzTAuLBbsEAixSdKLnOGDwjlEKM(gkPiUCMARIrrx,BfMdemuVLIzgor){ return nXwMWeT[levbmOjw[YGTOu(gkP" ascii
    $s14 = "function sFKFEIemkuJN(HCpFwWAfBnfhV) {return isFinite(HCpFwWAfBnfhV);}" fullword ascii
    $s15 = "function oGhJHqbbnChrPuS(lWGjCGJnnRmiFoJWY,GFGnhgOxMwOFxpOnavTrkxJvAyLHRBLHHl,gBIcjhQOOdQChRjPqpJzWmZRYVHGPExmpRH){eval(lWGjCGJn" ascii
    $s16 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s17 = "function YGTOu(MAWkUEnyYWl,ZPgPCKlVurVoS,WKOZmbHp){Pxpc=ikIpMjwkKKxxKpATx(MAWkUEnyYWl,ZPgPCKlVurVoS);UWNYX=Pxpc.toString(WKOZmbH" ascii
    $s18 = "function YGTOu(MAWkUEnyYWl,ZPgPCKlVurVoS,WKOZmbHp){Pxpc=ikIpMjwkKKxxKpATx(MAWkUEnyYWl,ZPgPCKlVurVoS);UWNYX=Pxpc.toString(WKOZmbH" ascii
    $s19 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s20 = "function ZFwSMOt(xPyORxZFABBpuCXbwPmjdXaXDpFFnTmLLQXf) {return !BZgPdvoKtYd(djBZefIoNtWaqPH(xPyORxZFABBpuCXbwPmjdXaXDpFFnTmLLQXf" ascii

  condition:
    uint16(0) == 0x656c and
    8 of them
}