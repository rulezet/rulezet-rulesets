rule sig_20160323_60d795750639ee75cf700726634ddce9 {
  meta:
    description = "datamaliciousorder - file 20160323_60d795750639ee75cf700726634ddce9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04f6d0d15a473b60a6cc237da15a37cba2178848bd31f5016599b5a5ac4dff7e"

  strings:
    $s1  = "return WScript.CreateObject(rTlOm);" fullword ascii
    $s2  = "var DF = true  , oNOa = iRg[7] + iRg[9] + iRg[11];" fullword ascii
    $s3  = "return mTFEEdH[0] + mTFEEdH[2] + mTFEEdH[4] + \".F\" + mTFEEdH[7] + mTFEEdH[9] + mTFEEdH[12] + mTFEEdH[14];" fullword ascii
    $s4  = "function VrDUDEPWe(KVCmD) {" fullword ascii
    $s5  = "XdtY.open(yqtzO,ftaCN,false);" fullword ascii
    $s6  = "var iRg = (\"2.XMLHTTP PuxGYib oYtFa XML ream St SXcZzAWH AD MTlpwFN O omST D\").split(\" \");" fullword ascii
    $s7  = "var mTFEEdH = QNrXf(IwbjqnvpGh+\" \"+\"System cz kfmTU Obj nJgvQG ect fQjamIO yejwG\", \" \");" fullword ascii
    $s8  = "vt = 1;CZVHC(WHA);ceIl(WHA,aVObzRj); try  {" fullword ascii
    $s9  = "function CZVHC(qUelCI) {" fullword ascii
    $s10 = "function ATAGc(tsQEgE) {" fullword ascii
    $s11 = "function WTysLmdo(TWe) {" fullword ascii
    $s12 = "JFs = K; break; " fullword ascii
    $s13 = "return uYVq.ExpandEnvironmentStrings(QxULj);" fullword ascii
    $s14 = "function QNrXf(sSM,VFWZz) {" fullword ascii
    $s15 = "return iSGGE.status;" fullword ascii
    $s16 = "function ceIl(nfQQZ,Krgma) {" fullword ascii
    $s17 = "function wIjp(ffaKF) {" fullword ascii
    $s18 = "if(K>=z.length) {break;}" fullword ascii
    $s19 = "function GIMN(GSEbM,gaRFa) {" fullword ascii
    $s20 = "return yinowHA(UA,Zjhps[325-319]+Zjhps[265-258]+Zjhps[277-269]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}