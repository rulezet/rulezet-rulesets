rule sig_20160411_8807ec84acb9c291eab5b6ee5dd7ee22 {
  meta:
    description = "datamaliciousorder - file 20160411_8807ec84acb9c291eab5b6ee5dd7ee22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a8c8bc6530be8b5c7bfc311dfb8bd80de61359a8c781c5a9f77c36c35549d9f"

  strings:
    $s1  = "return gdoORPE[0] + gdoORPE[2] + gdoORPE[4] + \".F\" + gdoORPE[7] + gdoORPE[9] + gdoORPE[12] + gdoORPE[14];" fullword ascii
    $s2  = "var xf = true  , qYTT = GUY[7] + GUY[9] + GUY[11];" fullword ascii
    $s3  = "var GUY = (\"2.XMLHTTP ZGqBeSL YmYNj XML ream St BsUbzCDV AD SUvMsFw O fGPv D\").split(\" \");" fullword ascii
    $s4  = "TtMW.open(edlIr,jnqTJ,false);" fullword ascii
    $s5  = "if(o>=L.length) {break;}" fullword ascii
    $s6  = "return ycRgo;" fullword ascii
    $s7  = "GNat(Ioy); Ioy.type = 1; muum(Ioy,NaQcXwQ(Bg)); if (zeFf(NAENwfTY(Ioy)))  {" fullword ascii
    $s8  = "function NaQcXwQ(IiTw) {" fullword ascii
    $s9  = "function ZClC(LMFoU) {" fullword ascii
    $s10 = "return xrW[oSNK[0]](TXpXk);" fullword ascii
    $s11 = "function zeFf(SeQsa) {" fullword ascii
    $s12 = "return fDSuyKL[0];" fullword ascii
    $s13 = "function tsyo(TcQQe) {" fullword ascii
    $s14 = "function lzKbGoYtg(trzYNNXIRmW) {" fullword ascii
    $s15 = "function XebSVnXX(gEyZ) {" fullword ascii
    $s16 = "return \"nvvVzysMqlFLIg\";" fullword ascii
    $s17 = "if (LMFoU == 486-286){return true;} else {return false;}" fullword ascii
    $s18 = "if (w >= TcQQe.length) {break;}" fullword ascii
    $s19 = "function pthMS(yxFSlpue,VyTD) {" fullword ascii
    $s20 = "return yizzsDh;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}