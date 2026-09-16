rule sig_20160314_c5027207d89eedf6139a0e790677e7b6 {
  meta:
    description = "datamaliciousorder - file 20160314_c5027207d89eedf6139a0e790677e7b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db2c2db59ed2977fd84e7fc1a6ae30d9e426fb0bb42775d0852a8712a4c7a514"

  strings:
    $s1  = "var WH = true  , JDdm = lmR[7] + lmR[9] + lmR[11];" fullword ascii
    $s2  = "return KmSZTfu[0] + KmSZTfu[2] + KmSZTfu[4] + \".F\" + KmSZTfu[7] + KmSZTfu[9] + KmSZTfu[12] + KmSZTfu[14];" fullword ascii
    $s3  = "var KmSZTfu = \"Sc PXGfQsT r hRekeGwjt ipting nKcvBRn jTa ile GaGNpJqrwCXaNQ System OV dJFau Obj pqcnEp ect WUFPnlB GSigx\".spli" ascii
    $s4  = "ahSjZ.open(KhzIB,uRKts,false);" fullword ascii
    $s5  = "var KmSZTfu = \"Sc PXGfQsT r hRekeGwjt ipting nKcvBRn jTa ile GaGNpJqrwCXaNQ System OV dJFau Obj pqcnEp ect WUFPnlB GSigx\".spli" ascii
    $s6  = "var lmR = (\"2.XMLHTTP YACVGMs KvIkV XML ream St XzPFQtys AD CNrBeVN O pHEI D\").split(\" \");" fullword ascii
    $s7  = "return XpK.size;" fullword ascii
    $s8  = "if (EAGGn > 159345-303){return true;} else {return false;}" fullword ascii
    $s9  = "function kwQicfiIv(QIvDThFqFvI) {" fullword ascii
    $s10 = "function tbkB(Dqhbl,SlbBQ) {" fullword ascii
    $s11 = "return ZbrxNis" fullword ascii
    $s12 = "function mJZt(ahSjZ,uRKts,KhzIB) {" fullword ascii
    $s13 = "function mxPi(wqswA) {" fullword ascii
    $s14 = "hsR = U; break; " fullword ascii
    $s15 = "function XIBb(UfDNz) {" fullword ascii
    $s16 = "if (bShnD == 861-661){return true;} else {return false;}" fullword ascii
    $s17 = "function FhYGa(TRgEmH) {" fullword ascii
    $s18 = "function ObPcHTmm() {" fullword ascii
    $s19 = "function ndwX(bUSuB) {" fullword ascii
    $s20 = "function oiwFAJgA(XpK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}