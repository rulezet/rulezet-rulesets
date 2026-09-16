rule sig_20160321_0f4974463ad25f44f26ab5565a9328a4 {
  meta:
    description = "datamaliciousorder - file 20160321_0f4974463ad25f44f26ab5565a9328a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06ad1ecc69908668d052ba331756dd02497b9afa1bfc532b7f83d661e8c33680"

  strings:
    $s1  = "return WScript.CreateObject(nvQcv);" fullword ascii
    $s2  = "return gHnOWEW[0] + gHnOWEW[2] + gHnOWEW[4] + \".F\" + gHnOWEW[7] + gHnOWEW[9] + gHnOWEW[12] + gHnOWEW[14];" fullword ascii
    $s3  = "var Zb = true  , cZqH = UAY[7] + UAY[9] + UAY[11];" fullword ascii
    $s4  = "var UAY = (\"2.XMLHTTP FtmdUnD tImJa XML ream St qqwAysHL AD aaQYaal O PEcH D\").split(\" \");" fullword ascii
    $s5  = "PqmoH.open(RloUR,fSbcs,false);" fullword ascii
    $s6  = "var gHnOWEW = KVTsW(zcVxOlquJI+\" \"+\"System JT mhwkJ Obj roYpzz ect SUqzZHL mCoWW\", \" \");" fullword ascii
    $s7  = "function GkRpixL(KgSV) {" fullword ascii
    $s8  = "function LYdDi(jyUJks) {" fullword ascii
    $s9  = "return hbVwADk(It,SeWEW[507-501]+SeWEW[644-637]+SeWEW[377-369]);" fullword ascii
    $s10 = "function hbVwADk(elKn,WrXJl) {" fullword ascii
    $s11 = "return jMd.split(NcHxr);" fullword ascii
    $s12 = "return elKn.ExpandEnvironmentStrings(WrXJl);" fullword ascii
    $s13 = "function ybMA(LERNJ) {" fullword ascii
    $s14 = "function VmqvWPWeE(OHrmO) {" fullword ascii
    $s15 = "function iHVFvzUe(PSFu) {" fullword ascii
    $s16 = "function eaBPh(iGpRNk) {" fullword ascii
    $s17 = "return viYwf;" fullword ascii
    $s18 = "if (g >= ploLa.length) {break;}" fullword ascii
    $s19 = "function CcvR(ploLa) {" fullword ascii
    $s20 = "function fjuM(EEJpI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}