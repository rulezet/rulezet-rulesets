rule sig_20151217_d4fa0dc537992e43cbae27a6c01f6abb {
  meta:
    description = "datamaliciousorder - file 20151217_d4fa0dc537992e43cbae27a6c01f6abb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0942fc7a7867b1405a06ad2332ddc264c81f2ea327578ffbe2966d6157348395"

  strings:
    $s1  = ") - 1));while(true){if (KEdQSIUCMGQ >= (3437+409)/641){break;}ZnmQeOKCc[KEdQSIUCMGQ]=Math.round((Math.pow(Math.sin(709), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(709), 2) - 1)); while(true) { if(ZnmQeOKCc[KEdQSIUCMGQ] > iOjrV[KEdQSIUCMGQ].length-(58+367)/425) { break; } if " ascii
    $s3  = "(Math.cos(912), 2) - 1)));} ZnmQeOKCc[KEdQSIUCMGQ]++;}KEdQSIUCMGQ++;} return XWNTdzeGXbj}" fullword ascii
    $s4  = "function WBqrBEeVlkukXXbcX(iOjrV){XWNTdzeGXbj= '';KEdQSIUCMGQ=Math.round((Math.pow(Math.sin(172), 2) + Math.pow(Math.cos(172), 2" ascii
    $s5  = "function WBqrBEeVlkukXXbcX(iOjrV){XWNTdzeGXbj= '';KEdQSIUCMGQ=Math.round((Math.pow(Math.sin(172), 2) + Math.pow(Math.cos(172), 2" ascii
    $s6  = "function pfDhjsl(tuZvOqktVJxyLfzsrPfVzSGWzvPYBFujzpxE) {return !xPfIepuqIRk(iqKfNGozAfjdbIv(tuZvOqktVJxyLfzsrPfVzSGWzvPYBFujzpxE" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "function iqKfNGozAfjdbIv(aqyRtHzDQiCNoYFpDaX) {return parseFloat(aqyRtHzDQiCNoYFpDaX);}" fullword ascii
    $s9  = "function pfDhjsl(tuZvOqktVJxyLfzsrPfVzSGWzvPYBFujzpxE) {return !xPfIepuqIRk(iqKfNGozAfjdbIv(tuZvOqktVJxyLfzsrPfVzSGWzvPYBFujzpxE" ascii
    $s10 = "function fTOwiOgpRyvpFASrnjOReeLFalMEflkUXHHyZsNzbcZsTLLvFGbBuq(asJiButCwIrBQ,WAjnicTyYbZqKR){ return EKtGDEK[kSAIjxhM[xfCnU(asJ" ascii
    $s11 = "function xPfIepuqIRk(jCSZAsLfFgOdjC) {return isNaN(jCSZAsLfFgOdjC);}" fullword ascii
    $s12 = "function AOkKqpkzfbVhWlZ(diFIEfNEzHKkQcLLH,UNTsMAzbDcNWLMsYUjpXxMMsdfimTcnMzS,QQPSBTDENYPabMxIbKcmvgQblJGzDKkaryO){eval(diFIEfNE" ascii
    $s13 = "function W(UeodtOPYZqwpyo,AtsNnRioRMMEE,BWYJjMpBkwH) {UeodtOPYZqwpyo[AtsNnRioRMMEE]=BWYJjMpBkwH;}" fullword ascii
    $s14 = "function fTOwiOgpRyvpFASrnjOReeLFalMEflkUXHHyZsNzbcZsTLLvFGbBuq(asJiButCwIrBQ,WAjnicTyYbZqKR){ return EKtGDEK[kSAIjxhM[xfCnU(asJ" ascii
    $s15 = "o);return jhukb;}" fullword ascii
    $s16 = "function gtCoJFPpQfvPpqjSi(HRonrdKKOX,pvMNiYkjrE) {return parseInt(HRonrdKKOX,pvMNiYkjrE);}" fullword ascii
    $s17 = "function AOkKqpkzfbVhWlZ(diFIEfNEzHKkQcLLH,UNTsMAzbDcNWLMsYUjpXxMMsdfimTcnMzS,QQPSBTDENYPabMxIbKcmvgQblJGzDKkaryO){eval(diFIEfNE" ascii
    $s18 = "function xfCnU(KUxrBnFnpNT,RmaMRGUmpLvMt,aKoHFSCo){PXHO=gtCoJFPpQfvPpqjSi(KUxrBnFnpNT,RmaMRGUmpLvMt);jhukb=PXHO.toString(aKoHFSC" ascii
    $s19 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s20 = "function xfCnU(KUxrBnFnpNT,RmaMRGUmpLvMt,aKoHFSCo){PXHO=gtCoJFPpQfvPpqjSi(KUxrBnFnpNT,RmaMRGUmpLvMt);jhukb=PXHO.toString(aKoHFSC" ascii

  condition:
    uint16(0) == 0x536b and
    8 of them
}