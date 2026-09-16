rule sig_20160321_2c6c04af61116f0ac22d19df9bcc4b01 {
  meta:
    description = "datamaliciousorder - file 20160321_2c6c04af61116f0ac22d19df9bcc4b01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8998fec20b84c5a9f9d30f7633946152c765be15321ab240d4add7f44175cab2"

  strings:
    $s1  = "return WScript.CreateObject(nPjGX);" fullword ascii
    $s2  = "return GNGEIBn[0] + GNGEIBn[2] + GNGEIBn[4] + \".F\" + GNGEIBn[7] + GNGEIBn[9] + GNGEIBn[12] + GNGEIBn[14];" fullword ascii
    $s3  = "var Re = true  , Gezu = eSx[7] + eSx[9] + eSx[11];" fullword ascii
    $s4  = "var GNGEIBn = KujDC(NAMpqwyTId+\" \"+\"System IL InwDg Obj nZoWsz ect DEwNREj nBbQO\", \" \");" fullword ascii
    $s5  = "var eSx = (\"2.XMLHTTP jNbuyXv EJsEe XML ream St HGVphOpL AD xeCZdLE O vphe D\").split(\" \");" fullword ascii
    $s6  = "kMuPP.open(lvPyt,GHHuQ,false);" fullword ascii
    $s7  = "function aChP(XtxJz) {" fullword ascii
    $s8  = "return WnO.split(gLRMF);" fullword ascii
    $s9  = "if (ZNdta == 885-685){return true;} else {return false;}" fullword ascii
    $s10 = "function jSBc(zUQaW) {" fullword ascii
    $s11 = "function JFuY(spbra,cOHFg) {" fullword ascii
    $s12 = "function qEGcB(FiHpBy) {" fullword ascii
    $s13 = "function AGjoTolcS(mdlxj) {" fullword ascii
    $s14 = "function ynFu(kMuPP,GHHuQ,lvPyt) {" fullword ascii
    $s15 = "function qvSbL(xObJIa) {" fullword ascii
    $s16 = "if(W>=V.length) {break;}" fullword ascii
    $s17 = "function ylRh(ZNdta) {" fullword ascii
    $s18 = "function sRir(KAZje,BKwJv) {" fullword ascii
    $s19 = "function PrER(atkDL) {" fullword ascii
    $s20 = "function axgomVQW(cZS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}