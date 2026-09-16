rule sig_20160411_6af27b34b094e17f7afa32a5d6e0bf15 {
  meta:
    description = "datamaliciousorder - file 20160411_6af27b34b094e17f7afa32a5d6e0bf15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c0a7fa346e9547bec833145e80cc086280f6ef0330abb84a11f92e5a05a1221"

  strings:
    $s1  = "return sauXFMu[0] + sauXFMu[2] + sauXFMu[4] + \".F\" + sauXFMu[7] + sauXFMu[9] + sauXFMu[12] + sauXFMu[14];" fullword ascii
    $s2  = "var Hy = true  , SblV = SBu[7] + SBu[9] + SBu[11];" fullword ascii
    $s3  = "var SBu = (\"2.XMLHTTP xTGfCHw syyUG XML ream St pGziExoH AD jTQosyN O xBQY D\").split(\" \");" fullword ascii
    $s4  = "yptp.open(gePtQ,kucJJ,false);" fullword ascii
    $s5  = "return nGL.size;" fullword ascii
    $s6  = "function sNas(fCvUN,kucJJ,gePtQ) {" fullword ascii
    $s7  = "ybJ = b; break; " fullword ascii
    $s8  = "function HPiHfOE(ejzY,dNyUS) {" fullword ascii
    $s9  = "if(b>=Z.length) {break;}" fullword ascii
    $s10 = "return new ActiveXObject(jqyO);" fullword ascii
    $s11 = "function jMnm(SzjFD) {" fullword ascii
    $s12 = "function GswN(oCdvs,YrRkW) {" fullword ascii
    $s13 = "function EWQE(hkrYz,wfsfD) {" fullword ascii
    $s14 = "function IxfxM(LAU,gXePj) {" fullword ascii
    $s15 = "return HPiHfOE(yN,axEsyq+rPCLb[601-593]);" fullword ascii
    $s16 = "function pEvJLC(jESD,nhakwo) {" fullword ascii
    $s17 = "function cfmIqnuAK(wRXcLAgrXDl) {" fullword ascii
    $s18 = "function XjOC(TqjtU) {" fullword ascii
    $s19 = "function gHxigWfw(nGL) {" fullword ascii
    $s20 = "function mcQRplQO(wZUI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}