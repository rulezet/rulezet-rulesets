rule sig_20151217_4f61399526022c54e68cd1c1dbe8f090 {
  meta:
    description = "datamaliciousorder - file 20151217_4f61399526022c54e68cd1c1dbe8f090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b65164c53e6e2d0385735ceec98f03f395b7133d8c6eda9d4cb6de2c5694b8ce"

  strings:
    $s1  = "(Math.cos(237), 2) - 1)));} yQYxBiGaX[lwGdfqSpyEF]++;}lwGdfqSpyEF++;} return LnusEFzRkin}" fullword ascii
    $s2  = ") - 1));while(true){if (lwGdfqSpyEF >= (5440+68)/918){break;}yQYxBiGaX[lwGdfqSpyEF]=Math.round((Math.pow(Math.sin(437), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(437), 2) - 1)); while(true) { if(yQYxBiGaX[lwGdfqSpyEF] > ckEui[lwGdfqSpyEF].length-(-15+436)/421) { break; } if " ascii
    $s4  = "function jTjMjBBMpxZQVHCeL(ckEui){LnusEFzRkin= '';lwGdfqSpyEF=Math.round((Math.pow(Math.sin(774), 2) + Math.pow(Math.cos(774), 2" ascii
    $s5  = "function jTjMjBBMpxZQVHCeL(ckEui){LnusEFzRkin= '';lwGdfqSpyEF=Math.round((Math.pow(Math.sin(774), 2) + Math.pow(Math.cos(774), 2" ascii
    $s6  = "function XoSGsgO(yJhuIKFCZTnKUDfdndSdPcXLbqnyyqwtHsTP) {return !nmsyeUEuTYN(VHIGlxAZCInrLNS(yJhuIKFCZTnKUDfdndSdPcXLbqnyyqwtHsTP" ascii
    $s7  = "f);return xkzPS;}" fullword ascii
    $s8  = "function x(DeAjKKDjspde,RhAIxpAjmzpzkI){DeAjKKDjspde.push(RhAIxpAjmzpzkI);}" fullword ascii
    $s9  = "function GQwlA(aQcLvzUJMTV,HAsmGUcoaqJGo,tVojgjaf){NmvR=WESGfXlFRBspSbWXi(aQcLvzUJMTV,HAsmGUcoaqJGo);xkzPS=NmvR.toString(tVojgja" ascii
    $s10 = "function uEsTxRGbnseljsK(QmgUiqSJBlzfOnDbO,DOpjwlnMjzMDGBpwTXKxRZmzNZcWIjOAdE,fGpcxdztpgycXIWONnQxLGmnUKTudkhOgRA){eval(QmgUiqSJ" ascii
    $s11 = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s12 = "function XoSGsgO(yJhuIKFCZTnKUDfdndSdPcXLbqnyyqwtHsTP) {return !nmsyeUEuTYN(VHIGlxAZCInrLNS(yJhuIKFCZTnKUDfdndSdPcXLbqnyyqwtHsTP" ascii
    $s13 = "function GQwlA(aQcLvzUJMTV,HAsmGUcoaqJGo,tVojgjaf){NmvR=WESGfXlFRBspSbWXi(aQcLvzUJMTV,HAsmGUcoaqJGo);xkzPS=NmvR.toString(tVojgja" ascii
    $s14 = "function nmsyeUEuTYN(JHFnOTlXnIwJxR) {return isNaN(JHFnOTlXnIwJxR);}" fullword ascii
    $s15 = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s16 = "function c(UQMFGBTtYCuSzC,rxHNYwjGOClVH,KDpnlEVwPHo) {UQMFGBTtYCuSzC[rxHNYwjGOClVH]=KDpnlEVwPHo;}" fullword ascii
    $s17 = "function WESGfXlFRBspSbWXi(ufTCOyANUO,wmlgsTCGiP) {return parseInt(ufTCOyANUO,wmlgsTCGiP);}" fullword ascii
    $s18 = "function uEsTxRGbnseljsK(QmgUiqSJBlzfOnDbO,DOpjwlnMjzMDGBpwTXKxRZmzNZcWIjOAdE,fGpcxdztpgycXIWONnQxLGmnUKTudkhOgRA){eval(QmgUiqSJ" ascii
    $s19 = "function VHIGlxAZCInrLNS(okXDOsRehOlDGzcpFiZ) {return parseFloat(okXDOsRehOlDGzcpFiZ);}" fullword ascii
    $s20 = "function mfmJKgLQvlfS(UCFdcoDSCeKJH) {return isFinite(UCFdcoDSCeKJH);}" fullword ascii

  condition:
    uint16(0) == 0x5647 and
    8 of them
}