rule sig_20160310_69729b0b2543ff963e1018caed0b0cb4 {
  meta:
    description = "datamaliciousorder - file 20160310_69729b0b2543ff963e1018caed0b0cb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc28d0fa881c1bf32aa1aba9ecc8a3aa4a90b4e718045effa8b43e0006fff2dc"

  strings:
    $s1  = "return qdstQii[0] + qdstQii[2] + qdstQii[4] + \".F\" + qdstQii[7] + qdstQii[9] + qdstQii[12] + qdstQii[14];" fullword ascii
    $s2  = "var FQ = true  , WqmF = PTK[7] + PTK[9] + PTK[11];" fullword ascii
    $s3  = "var PTK = (\"2.XMLHTTP zsDkhmq rZLsT XML ream St RzYDdZFo AD bSKgLET O uffn D\").split(\" \");" fullword ascii
    $s4  = "var qdstQii = \"Sc UmLjBrR r JcSAnORAs ipting rbOaHfd tJu ile KYGEBKerFnWGRN System Ka vpIfO Obj vbGpZY ect RmCiJpI\".split(\" " ascii
    $s5  = "orIVR.open(UZryb,mtSuv,false);" fullword ascii
    $s6  = "if(t>=S.length) {break;}" fullword ascii
    $s7  = "mmY = t; break; " fullword ascii
    $s8  = "function FRAVsYVnD(MWMoX,JDCXA,qpoRZ,pTTz) {" fullword ascii
    $s9  = "function gLMCrENI(FMmbg,QcogLz) {" fullword ascii
    $s10 = "function FqEXn(DvWFZI) {" fullword ascii
    $s11 = "function ezkA(UAOhD) {" fullword ascii
    $s12 = "return DDnfvzc(LK,UWJcR[765-759]+UWJcR[589-582]+UWJcR[130-122]);" fullword ascii
    $s13 = "return QeP.size;" fullword ascii
    $s14 = "function DDnfvzc(bJVX,ayedZ) {" fullword ascii
    $s15 = "return bJVX.ExpandEnvironmentStrings(ayedZ);" fullword ascii
    $s16 = "return PKvih;" fullword ascii
    $s17 = "function VTYyOCkE() {" fullword ascii
    $s18 = "function sKrh(sesIh) {" fullword ascii
    $s19 = "function PZmQ(upFfv) {" fullword ascii
    $s20 = "if (n >= cRjAm.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}