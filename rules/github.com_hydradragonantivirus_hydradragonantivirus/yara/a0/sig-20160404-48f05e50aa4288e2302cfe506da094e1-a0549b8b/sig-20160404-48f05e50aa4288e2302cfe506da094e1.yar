rule sig_20160404_48f05e50aa4288e2302cfe506da094e1 {
  meta:
    description = "datamaliciousorder - file 20160404_48f05e50aa4288e2302cfe506da094e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c918d91433422a79960d86997ed23417f12446475014360f7fb076ddb4af2c"

  strings:
    $s1  = "return DIdnrOk[0] + DIdnrOk[2] + DIdnrOk[4] + \".F\" + DIdnrOk[7] + DIdnrOk[9] + DIdnrOk[12] + DIdnrOk[14];" fullword ascii
    $s2  = "var vY = true  , jTgd = DWm[7] + DWm[9] + DWm[11];" fullword ascii
    $s3  = "var DWm = (\"2.XMLHTTP shiTtwO pUwcx XML ream St iPLwnvYS AD tgHmtVL O LUNU D\").split(\" \");" fullword ascii
    $s4  = "return FGTmpMG;" fullword ascii
    $s5  = "var DIdnrOk = zoHjF(mWyoFQHpKF+\" \"+\"System LN igjtD Obj xCpDFG ect OgVZQmO WOQcS\", \" \");" fullword ascii
    $s6  = "sXER.open(iwQbi,AXEIG,false);" fullword ascii
    $s7  = "function hFdb(fRVNO) {" fullword ascii
    $s8  = "function lDcVfXHN(trN) {" fullword ascii
    $s9  = "function lhSN(Utuoq,NjjrK) {" fullword ascii
    $s10 = "function SjtnhRp(TQGU) {" fullword ascii
    $s11 = "MkS = j; break; " fullword ascii
    $s12 = "return cHh.split(gnWlg);" fullword ascii
    $s13 = "return TQGU[NyjVpi[0]];" fullword ascii
    $s14 = "function zzNYgG(bcLy,yLXZmi) {" fullword ascii
    $s15 = "function nVCW(usmDf) {" fullword ascii
    $s16 = "function xWkUA(hKIugzsE,LBbx) {" fullword ascii
    $s17 = "function IqZt(vrkRv,SBGfE) {" fullword ascii
    $s18 = "function OuvFu(mJllmH) {" fullword ascii
    $s19 = "if (Y >= qGJfP.length) {break;}" fullword ascii
    $s20 = "function zDfG(QIeTT,AXEIG,iwQbi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}