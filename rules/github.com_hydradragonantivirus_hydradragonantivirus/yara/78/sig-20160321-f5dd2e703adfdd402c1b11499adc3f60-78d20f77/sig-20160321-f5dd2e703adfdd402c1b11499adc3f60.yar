rule sig_20160321_f5dd2e703adfdd402c1b11499adc3f60 {
  meta:
    description = "datamaliciousorder - file 20160321_f5dd2e703adfdd402c1b11499adc3f60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "697778200224dbda09fe853bf8a73291b65752b59c8c2a3716b5851b704c57ee"

  strings:
    $s1  = "return WScript.CreateObject(tgYTb);" fullword ascii
    $s2  = "var jF = true  , QZep = CPR[7] + CPR[9] + CPR[11];" fullword ascii
    $s3  = "return YMbisQc[0] + YMbisQc[2] + YMbisQc[4] + \".F\" + YMbisQc[7] + YMbisQc[9] + YMbisQc[12] + YMbisQc[14];" fullword ascii
    $s4  = "hFxyN.open(DrIFV,ElyWB,false);" fullword ascii
    $s5  = "var CPR = (\"2.XMLHTTP zPpVlZS KwgSf XML ream St JFAeajMZ AD OrEqHMN O Anjl D\").split(\" \");" fullword ascii
    $s6  = "var YMbisQc = QGWlU(vQMgmNrxmU+\" \"+\"System cf VnmGc Obj fjWpgc ect uxRNdmW CqiAy\", \" \");" fullword ascii
    $s7  = "if(p>=N.length) {break;}" fullword ascii
    $s8  = "function hMCI(sLhCh,XvRcK) {" fullword ascii
    $s9  = "function tZmkrUeu(SQIO) {" fullword ascii
    $s10 = "function YTeN(fVxJA) {" fullword ascii
    $s11 = "function KWzv(tgYTb) {" fullword ascii
    $s12 = "function MjtFz(zYBlla) {" fullword ascii
    $s13 = "return cNreRQZ(GK,vaulJ[733-727]+vaulJ[783-776]+vaulJ[553-545]);" fullword ascii
    $s14 = "function cNreRQZ(DKFI,GkhLV) {" fullword ascii
    $s15 = "function tpaDeVjU(aRT) {" fullword ascii
    $s16 = "if (I >= fVxJA.length) {break;}" fullword ascii
    $s17 = "return mXZz[SwLtGu[0]];" fullword ascii
    $s18 = "return PaCLE;" fullword ascii
    $s19 = "function MDeD(hFxyN,ElyWB,DrIFV) {" fullword ascii
    $s20 = "CgH = p; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}