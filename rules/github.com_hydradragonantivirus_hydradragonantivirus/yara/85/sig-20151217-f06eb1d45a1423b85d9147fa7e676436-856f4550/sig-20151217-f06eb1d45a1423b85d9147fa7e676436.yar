rule sig_20151217_f06eb1d45a1423b85d9147fa7e676436 {
  meta:
    description = "datamaliciousorder - file 20151217_f06eb1d45a1423b85d9147fa7e676436.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77f31028cf76a74c453a6bdf43a562fcb47d904959685264c8676d4bb9a279d5"

  strings:
    $s1  = "(Math.cos(401), 2) - 1)));} fQKWAtYvq[bhiTJJJZrtw]++;}bhiTJJJZrtw++;} return MQWINYIbZTv}" fullword ascii
    $s2  = ") - 1));while(true){if (bhiTJJJZrtw >= (4226+676)/817){break;}fQKWAtYvq[bhiTJJJZrtw]=Math.round((Math.pow(Math.sin(933), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(933), 2) - 1)); while(true) { if(fQKWAtYvq[bhiTJJJZrtw] > kTpsb[bhiTJJJZrtw].length-(-122+949)/827) { break; } i" ascii
    $s4  = "function xrtvrKTmjBnlfBkXP(kTpsb){MQWINYIbZTv= '';bhiTJJJZrtw=Math.round((Math.pow(Math.sin(782), 2) + Math.pow(Math.cos(782), 2" ascii
    $s5  = "function xrtvrKTmjBnlfBkXP(kTpsb){MQWINYIbZTv= '';bhiTJJJZrtw=Math.round((Math.pow(Math.sin(782), 2) + Math.pow(Math.cos(782), 2" ascii
    $s6  = "function GqVtuUd(jrvTLYtrxXeQkBoxUVFIhLptvRXaervdhSwb) {return !gTLOzzJQcCo(sGePpYIvkixEFQd(jrvTLYtrxXeQkBoxUVFIhLptvRXaervdhSwb" ascii
    $s7  = ",'u','V','L','3','l','j','T','W','C','<','X','#','p','B','E','Y','>','!',',','i','i','F','Z','X','b','[','0','W','^',']',String." ascii
    $s8  = "function oUKqVJEJkzrdAhjFW(xGYrMFkEXh,zWDtweVzrE) {return parseInt(xGYrMFkEXh,zWDtweVzrE);}" fullword ascii
    $s9  = "function fjTHdRQVdRydXHQ(ZgAaqnKmKTXhaZcWs,ZkBpfxGULIGpGaSwLGtnSlkBwAnFqEhsId,zcsQLkSyqKONLZvcrWmRGkOhDiyBSBdyPwo){eval(ZgAaqnKm" ascii
    $s10 = "function gTLOzzJQcCo(gxYCGzpqUPVVqc) {return isNaN(gxYCGzpqUPVVqc);}" fullword ascii
    $s11 = "function JIRxhxAmyquFtUpiOGhzidJwPKRuilXchrLUIOUCyOJYxvMWlRkhvR(fHnBauMcdCWBw,cBizgWcbmhUsGe){ return spoKaiQ[knaxKHmK[qqZtY(fHn" ascii
    $s12 = "function T(BbKBydLNroZU,kmnJYAasmeOUOK){BbKBydLNroZU.push(kmnJYAasmeOUOK);}" fullword ascii
    $s13 = "function JIRxhxAmyquFtUpiOGhzidJwPKRuilXchrLUIOUCyOJYxvMWlRkhvR(fHnBauMcdCWBw,cBizgWcbmhUsGe){ return spoKaiQ[knaxKHmK[qqZtY(fHn" ascii
    $s14 = "function sGePpYIvkixEFQd(NVGOnscbPZuPHCONYvC) {return parseFloat(NVGOnscbPZuPHCONYvC);}" fullword ascii
    $s15 = "z);return fNqlE;}" fullword ascii
    $s16 = "function fjTHdRQVdRydXHQ(ZgAaqnKmKTXhaZcWs,ZkBpfxGULIGpGaSwLGtnSlkBwAnFqEhsId,zcsQLkSyqKONLZvcrWmRGkOhDiyBSBdyPwo){eval(ZgAaqnKm" ascii
    $s17 = "function qqZtY(RJPjcJCVxSL,QCeUSyDRuQKwO,DyVZwYkz){GfUL=oUKqVJEJkzrdAhjFW(RJPjcJCVxSL,QCeUSyDRuQKwO);fNqlE=GfUL.toString(DyVZwYk" ascii
    $s18 = "function ZjirddgFUrGQ(WjCBOFRbaPvmt) {return isFinite(WjCBOFRbaPvmt);}" fullword ascii
    $s19 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s20 = "function qqZtY(RJPjcJCVxSL,QCeUSyDRuQKwO,DyVZwYkz){GfUL=oUKqVJEJkzrdAhjFW(RJPjcJCVxSL,QCeUSyDRuQKwO);fNqlE=GfUL.toString(DyVZwYk" ascii

  condition:
    uint16(0) == 0x6e6b and
    8 of them
}