rule sig_20160322_76c938f59b3fa248ad72d582ee95468d {
  meta:
    description = "datamaliciousorder - file 20160322_76c938f59b3fa248ad72d582ee95468d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d29367857ec9318e67557d5e5bc27af89a995410e43e9d21f907d1ce45595f88"

  strings:
    $s1  = "return WScript.CreateObject(nxaeq);" fullword ascii
    $s2  = "return aBaAFVr[0] + aBaAFVr[2] + aBaAFVr[4] + \".F\" + aBaAFVr[7] + aBaAFVr[9] + aBaAFVr[12] + aBaAFVr[14];" fullword ascii
    $s3  = "var WC = true  , XlIQ = lAd[7] + lAd[9] + lAd[11];" fullword ascii
    $s4  = "var lAd = (\"2.XMLHTTP hkLrXiH MDfJV XML ream St bDiSBgfv AD OoVtfxq O bSOl D\").split(\" \");" fullword ascii
    $s5  = "var aBaAFVr = hCuRF(SmcTULMyHj+\" \"+\"System bh Fgvcm Obj jIYiBx ect RQWrHyw KEbdp\", \" \");" fullword ascii
    $s6  = "AUjk.open(osFtu,ljFUl,false);" fullword ascii
    $s7  = "function dEie(yjmur) {" fullword ascii
    $s8  = "if (SSecx == 944-744){return true;} else {return false;}" fullword ascii
    $s9  = "return KUb.split(vNmpW);" fullword ascii
    $s10 = "function JIOjOmIK(RKJf) {" fullword ascii
    $s11 = "function TZfgvKnV(FrL) {" fullword ascii
    $s12 = "function FTwH(SSecx) {" fullword ascii
    $s13 = "function NZEjNIx(iSHh) {" fullword ascii
    $s14 = "return FrL.size;" fullword ascii
    $s15 = "return sRAVyw.position=203-203;" fullword ascii
    $s16 = "return AXkfXKg(gy,uDwwQ[645-639]+uDwwQ[754-747]+uDwwQ[621-613]);" fullword ascii
    $s17 = "return bAWwd.status;" fullword ascii
    $s18 = "function MQGo(IZCTH,qhwUW) {" fullword ascii
    $s19 = "function dRnC(qFDaW,ljFUl,osFtu) {" fullword ascii
    $s20 = "function uUjrc(sRAVyw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}