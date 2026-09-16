rule sig_20160323_282bf0f91d5ee57b71d008e50a51e439 {
  meta:
    description = "datamaliciousorder - file 20160323_282bf0f91d5ee57b71d008e50a51e439.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a07f6656a09b66f1b217214d31a5e8b8591d2b0b87870a7db481c063dd4f7b8b"

  strings:
    $s1  = "return WScript.CreateObject(rxdvi);" fullword ascii
    $s2  = "var uD = true  , gefx = Zaf[7] + Zaf[9] + Zaf[11];" fullword ascii
    $s3  = "return BiCIJsq[0] + BiCIJsq[2] + BiCIJsq[4] + \".F\" + BiCIJsq[7] + BiCIJsq[9] + BiCIJsq[12] + BiCIJsq[14];" fullword ascii
    $s4  = "var Zaf = (\"2.XMLHTTP SNKmtNs rKlOp XML ream St hgMkxKLM AD UKgViwC O fukx D\").split(\" \");" fullword ascii
    $s5  = "var BiCIJsq = xRaOh(LqiUlosTkD+\" \"+\"System pS AOVmW Obj FEryYd ect KzpdMxy vaoAj\", \" \");" fullword ascii
    $s6  = "pRhK.open(mkBrS,QUrrK,false);" fullword ascii
    $s7  = "function GAtU(IWYLh) {" fullword ascii
    $s8  = "if (K >= wAClH.length) {break;}" fullword ascii
    $s9  = "function vhBx(wAClH) {" fullword ascii
    $s10 = "return cKjB[ZTHULA[0]];" fullword ascii
    $s11 = "return oYD.split(yUiEB);" fullword ascii
    $s12 = "function TyQF(rxdvi) {" fullword ascii
    $s13 = "QQo = d; break; " fullword ascii
    $s14 = "function WyHw(RWomh,jVhAL) {" fullword ascii
    $s15 = "return cmsmrPA(Nv,DSaXR[530-524]+DSaXR[608-601]+DSaXR[385-377]);" fullword ascii
    $s16 = "function cmsmrPA(xUNj,HtatW) {" fullword ascii
    $s17 = "function RLWMplLOq(eAILv) {" fullword ascii
    $s18 = "function XeWrDtIy(Zxdy) {" fullword ascii
    $s19 = "function mYQu(ehdZA) {" fullword ascii
    $s20 = "return xUNj.ExpandEnvironmentStrings(HtatW);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}