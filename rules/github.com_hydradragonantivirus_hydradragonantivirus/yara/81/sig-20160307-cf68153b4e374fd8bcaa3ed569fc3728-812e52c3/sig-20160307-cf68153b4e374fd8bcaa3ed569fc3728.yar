rule sig_20160307_cf68153b4e374fd8bcaa3ed569fc3728 {
  meta:
    description = "datamaliciousorder - file 20160307_cf68153b4e374fd8bcaa3ed569fc3728.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7221340b4d2c5062668cd4b95335a4b99cf45a48cf8827f8dc8f1895d1a22c0"

  strings:
    $s1  = "var Ef = true  , RjUV = ytM[7] + ytM[9] + ytM[11];" fullword ascii
    $s2  = "return vQKUUzr[0] + vQKUUzr[2] + vQKUUzr[4] + \".F\" + vQKUUzr[7] + vQKUUzr[9] + vQKUUzr[12] + vQKUUzr[14];" fullword ascii
    $s3  = "OGVis.open(LtMUo,ygMeY,false);" fullword ascii
    $s4  = "var ytM = (\"2.XMLHTTP zywEvrZ nAYoH XML ream St jcyhJEtZ AD eUaZNMX O gady D\").split(\" \");" fullword ascii
    $s5  = "var vQKUUzr = \"Sc dlHLKlF r hCrofeNCD ipting HIdqDgL Kwj ile PDhajlwvsjsDeE System DZ QTfVz Obj JZUTKM ect clihqkT\".split(\" " ascii
    $s6  = "function BjBR(NqDYh) {" fullword ascii
    $s7  = "function Qqdp(XkOOQ) {" fullword ascii
    $s8  = "function MZzg(OGVis,ygMeY,LtMUo) {" fullword ascii
    $s9  = "function cdZOQeGUq(osPZDVrbNEn) {" fullword ascii
    $s10 = "function HjZQ(IqPvA,xjfem) {" fullword ascii
    $s11 = "if (O >= xpbcc.length) {break;}" fullword ascii
    $s12 = "function gbYB(xpbcc) {" fullword ascii
    $s13 = "return LP.ExpandEnvironmentStrings(gvKUU[6]+gvKUU[7]+gvKUU[8]);" fullword ascii
    $s14 = "return yLsOA;" fullword ascii
    $s15 = "function oiCsooOX() {" fullword ascii
    $s16 = "function vKBEp(EPqGIM) {" fullword ascii
    $s17 = "return smN.size;" fullword ascii
    $s18 = "return MTwp.responseBody;" fullword ascii
    $s19 = "return NqDYh.status;" fullword ascii
    $s20 = "function plDD(AkhXc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}