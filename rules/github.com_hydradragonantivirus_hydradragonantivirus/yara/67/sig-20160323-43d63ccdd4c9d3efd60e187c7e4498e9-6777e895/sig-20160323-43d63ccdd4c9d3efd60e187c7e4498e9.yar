rule sig_20160323_43d63ccdd4c9d3efd60e187c7e4498e9 {
  meta:
    description = "datamaliciousorder - file 20160323_43d63ccdd4c9d3efd60e187c7e4498e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abeb598fdab86f6663915f2abfd9ce4f0d6b512e5f7a85a07bae2f09e01fd8ca"

  strings:
    $s1  = "return WScript.CreateObject(iPljE);" fullword ascii
    $s2  = "return QKThYpy[0] + QKThYpy[2] + QKThYpy[4] + \".F\" + QKThYpy[7] + QKThYpy[9] + QKThYpy[12] + QKThYpy[14];" fullword ascii
    $s3  = "var Hm = true  , kcPE = xIE[7] + xIE[9] + xIE[11];" fullword ascii
    $s4  = "var xIE = (\"2.XMLHTTP cTbohQV fmNHC XML ream St XpziqSkX AD PfWCOny O WSTQ D\").split(\" \");" fullword ascii
    $s5  = "OCeV.open(ixfMv,ruWDt,false);" fullword ascii
    $s6  = "var QKThYpy = JeROE(nTCeikDZVM+\" \"+\"System st LfjXv Obj pByyrq ect AEClOoW TNcBb\", \" \");" fullword ascii
    $s7  = "function YTmb(kSVVX,ruWDt,ixfMv) {" fullword ascii
    $s8  = "function TKqjQCw(CqQW) {" fullword ascii
    $s9  = "if(N>=q.length) {break;}" fullword ascii
    $s10 = "function TbrJKprbr(xBWSjKXpKzN) {" fullword ascii
    $s11 = "if (SrBOh == 1164-964){return true;} else {return false;}" fullword ascii
    $s12 = "function YuMJIvsJF(Okzbj) {" fullword ascii
    $s13 = "return new ActiveXObject(shJX);" fullword ascii
    $s14 = "function EvUAU(pBMnlc) {" fullword ascii
    $s15 = "function AUIxd(UZHbMd) {" fullword ascii
    $s16 = "return pBMnlc/*4VqaViODaEaloWNdOqsajur2d*/.position=978-978;" fullword ascii
    $s17 = "function vCfU(JzpGr) {" fullword ascii
    $s18 = "KwP = N; break; " fullword ascii
    $s19 = "if (jxWVf > 160181-364){return true;} else {return false;}" fullword ascii
    $s20 = "function qsOCNexd(XOF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}