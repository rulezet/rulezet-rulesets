rule sig_20160314_640d9d9dcee3a0a85a660d3943578d0f {
  meta:
    description = "datamaliciousorder - file 20160314_640d9d9dcee3a0a85a660d3943578d0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caa6e44b7d71cfd2190f9940a41fed40b540cc0ef5694048ed77a2b304c49fde"

  strings:
    $s1  = "var YS = true  , Jvgh = Wdw[7] + Wdw[9] + Wdw[11];" fullword ascii
    $s2  = "return GJrYDUq[0] + GJrYDUq[2] + GJrYDUq[4] + \".F\" + GJrYDUq[7] + GJrYDUq[9] + GJrYDUq[12] + GJrYDUq[14];" fullword ascii
    $s3  = "var GJrYDUq = \"Sc JYqNxFY r lxcbpYLqX ipting lKyYuKu hVB ile MHuZExVRBMzDtu System yP AIWCV Obj iSGarN ect ElXohaw zWJTG\".spli" ascii
    $s4  = "var GJrYDUq = \"Sc JYqNxFY r lxcbpYLqX ipting lKyYuKu hVB ile MHuZExVRBMzDtu System yP AIWCV Obj iSGarN ect ElXohaw zWJTG\".spli" ascii
    $s5  = "var Wdw = (\"2.XMLHTTP lzUSOnr aDIZk XML ream St JefEgxDy AD QYvfqze O Ieol D\").split(\" \");" fullword ascii
    $s6  = "VsWCN.open(bSvlb,YrzST,false);" fullword ascii
    $s7  = "function pONi(PhCWG) {" fullword ascii
    $s8  = "if(G>=R.length) {break;}" fullword ascii
    $s9  = "return PhCWG.status;" fullword ascii
    $s10 = "function RLenCheXY(IVLIeCUFezY) {" fullword ascii
    $s11 = "function ZJRRrXz(mPsC) {" fullword ascii
    $s12 = "WLD = G; break; " fullword ascii
    $s13 = "return TrAri;" fullword ascii
    $s14 = "function hyqs(bRPsN) {" fullword ascii
    $s15 = "return new ActiveXObject(NTGWln);" fullword ascii
    $s16 = "function ibUOyyvq(nJK) {" fullword ascii
    $s17 = "if (gESno == 309-109){return true;} else {return false;}" fullword ascii
    $s18 = "function eYGY(BlnzS) {" fullword ascii
    $s19 = "function OUuz(xsdQP) {" fullword ascii
    $s20 = "function UHdmt(NTGWln) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}