rule sig_20160311_35d0b12bd8ef5b71a66a0c54a5b08b25 {
  meta:
    description = "datamaliciousorder - file 20160311_35d0b12bd8ef5b71a66a0c54a5b08b25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2bc6e8ad15fc6a9bea5087d8a56a26cedc3e15ad22594e1a4407fa3e570bb3c"

  strings:
    $s1  = "function BsyU(qftPe) {" fullword ascii
    $s2  = "var Qe = true  , mAmC = sbt[7] + sbt[9] + sbt[11];" fullword ascii
    $s3  = "return Uijmiuy[0] + Uijmiuy[2] + Uijmiuy[4] + \".F\" + Uijmiuy[7] + Uijmiuy[9] + Uijmiuy[12] + Uijmiuy[14];" fullword ascii
    $s4  = "var Uijmiuy = \"Sc LRRNafi r LWfcBLuWX ipting smsMaBx MTu ile WMnORJKLGezwai System yw NaFyg Obj Umximt ect llmQHsJ\".split(\" " ascii
    $s5  = "ATRAX.open(mpBSP,taGdA,false);" fullword ascii
    $s6  = "var sbt = (\"2.XMLHTTP kkiLzkd GLfyC XML ream St WvtIyITQ AD gHUTDvh O HpDw D\").split(\" \");" fullword ascii
    $s7  = "function inNdrzi(DqOL) {" fullword ascii
    $s8  = "return lXyevnI" fullword ascii
    $s9  = "function QoBi(fvthB,cKRnL) {" fullword ascii
    $s10 = "function HDTT(CcPHJ) {" fullword ascii
    $s11 = "if (pPRzO == 592-392){return true;} else {return false;}" fullword ascii
    $s12 = "return DqOL.responseBody;" fullword ascii
    $s13 = "return mrb.size;" fullword ascii
    $s14 = "function HIbm(HbnhQ) {" fullword ascii
    $s15 = "return CmsOF;" fullword ascii
    $s16 = "function QRYa(pPRzO) {" fullword ascii
    $s17 = "return bhLnY.status;" fullword ascii
    $s18 = "yli = F; break; " fullword ascii
    $s19 = "function KXxbZ(CyQzOZ) {" fullword ascii
    $s20 = "function xmzi(ATRAX,taGdA,mpBSP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}