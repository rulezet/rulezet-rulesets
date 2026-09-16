rule sig_20160307_94e349b31c86d64095c8fa78f3629d74 {
  meta:
    description = "datamaliciousorder - file 20160307_94e349b31c86d64095c8fa78f3629d74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10bf8a025f0b310167ed59cd180e7f7bae2b5e14eae134a97664ccbe047c7cec"

  strings:
    $s1  = "var UD = true  , VEHq = PIg[7] + PIg[9] + PIg[11];" fullword ascii
    $s2  = "return ULMORpt[0] + ULMORpt[2] + ULMORpt[4] + \".F\" + ULMORpt[7] + ULMORpt[9] + ULMORpt[12] + ULMORpt[14];" fullword ascii
    $s3  = "var ULMORpt = \"Sc AIxOYvR r nHPjNvemT ipting uUOIGDQ KwW ile osmeNBYrbKHFHu System pE XicSx Obj XnvJdF ect NYGcOYD\".split(\" " ascii
    $s4  = "var PIg = (\"2.XMLHTTP EigaSNv SzVCN XML ream St vabLdiSp AD EiLMviY O RpyG D\").split(\" \");" fullword ascii
    $s5  = "REzSj.open(ZccXD,lHOuZ,false);" fullword ascii
    $s6  = "return FcFAZ.status;" fullword ascii
    $s7  = "function VYgV(PPdgD) {" fullword ascii
    $s8  = "function imZuMJxAC(mElfR,LZNcH,dSOxI,hfow) {" fullword ascii
    $s9  = "function rMPh(oRwRF) {" fullword ascii
    $s10 = "function yUhgFjee() {" fullword ascii
    $s11 = "function XPDW(Uhqjw) {" fullword ascii
    $s12 = "if (z >= PPdgD.length) {break;}" fullword ascii
    $s13 = "return Vg.ExpandEnvironmentStrings(ZXewg[6]+ZXewg[7]+ZXewg[8]);" fullword ascii
    $s14 = "return miFWDIy" fullword ascii
    $s15 = "if (Uhqjw > 189173-273){return true;} else {return false;}" fullword ascii
    $s16 = "function eyHK(FcFAZ) {" fullword ascii
    $s17 = "function VBjH(VZXue) {" fullword ascii
    $s18 = "if (oRwRF == 1070-870){return true;} else {return false;}" fullword ascii
    $s19 = "function PtSb(OhnuN) {" fullword ascii
    $s20 = "if(o>=W.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}