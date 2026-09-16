rule sig_20160404_744c43424ca4a5243494c960921ca500 {
  meta:
    description = "datamaliciousorder - file 20160404_744c43424ca4a5243494c960921ca500.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99cd2210201c2c0a5e7e9d6deed6e1406ff195b28503b8926ab4d21ef2c89b02"

  strings:
    $s1  = "return WUXNcmD[0] + WUXNcmD[2] + WUXNcmD[4] + \".F\" + WUXNcmD[7] + WUXNcmD[9] + WUXNcmD[12] + WUXNcmD[14];" fullword ascii
    $s2  = "var WUXNcmD = TMOoM(qqPzMATkZc+\" \"+\"System Gk JSfRm Obj PEdOSn ect OFJcWqM pcoFL\", \" \");" fullword ascii
    $s3  = "var zJ = true  , vEWo = KHt[7] + KHt[9] + KHt[11];" fullword ascii
    $s4  = "gntV.open(eLhFl,gtMuD,false);" fullword ascii
    $s5  = "var KHt = (\"2.XMLHTTP uhcxxHC DtOct XML ream St RpGtTIlO AD WTIvnGd O acCi D\").split(\" \");" fullword ascii
    $s6  = "function vcUd(otvsX) {" fullword ascii
    $s7  = "function jeDM(nuXVw,veFAW) {" fullword ascii
    $s8  = "function wkLwGjZ(UMCE) {" fullword ascii
    $s9  = "function LTxvolekz(KullPPhRCDl) {" fullword ascii
    $s10 = "return oItzgHe;" fullword ascii
    $s11 = "return Cphyffu(Gl,UJfSR[561-555]+UJfSR[685-678]+UJfSR[358-350]);" fullword ascii
    $s12 = "return vIyc;" fullword ascii
    $s13 = "if (nLsvY > 162517-364){return true;} else {return false;}" fullword ascii
    $s14 = "if(J>=w.length) {break;}" fullword ascii
    $s15 = "function wloai(RvJkbz) {" fullword ascii
    $s16 = "function cxRTYZoa(Vbgg) {" fullword ascii
    $s17 = "gCL = J; break; " fullword ascii
    $s18 = "return QECEW;" fullword ascii
    $s19 = "return new ActiveXObject(hAQB);" fullword ascii
    $s20 = "function kGRxCR(ooPF,beIVvx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}