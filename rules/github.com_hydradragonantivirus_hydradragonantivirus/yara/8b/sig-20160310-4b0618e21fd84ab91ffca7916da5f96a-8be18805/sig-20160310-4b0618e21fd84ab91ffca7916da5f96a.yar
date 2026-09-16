rule sig_20160310_4b0618e21fd84ab91ffca7916da5f96a {
  meta:
    description = "datamaliciousorder - file 20160310_4b0618e21fd84ab91ffca7916da5f96a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0378243d4f24e20fd83acf22b7c846fc223eda56d18b7d62773b6112c83d281"

  strings:
    $s1  = "var ho = true  , XgcX = xuz[7] + xuz[9] + xuz[11];" fullword ascii
    $s2  = "return rRJOpKH[0] + rRJOpKH[2] + rRJOpKH[4] + \".F\" + rRJOpKH[7] + rRJOpKH[9] + rRJOpKH[12] + rRJOpKH[14];" fullword ascii
    $s3  = "var rRJOpKH = \"Sc MUbzIzv r BNfktLVwy ipting FTzDtZU ZDN ile yLHbGpWmaoetzi System zK wVPuv Obj LZxsYd ect EcCYVlZ\".split(\" " ascii
    $s4  = "YiHFg.open(uJFjD,YXEgj,false);" fullword ascii
    $s5  = "var xuz = (\"2.XMLHTTP izYsyJG etdnS XML ream St ZRTwYIrs AD ZixEwSR O jWae D\").split(\" \");" fullword ascii
    $s6  = "return deKnJB.position=650-650;" fullword ascii
    $s7  = "function ZpjnSfnEw(djNPz,KmFRk,oXGIA,iOqN) {" fullword ascii
    $s8  = "function KBFxX(deKnJB) {" fullword ascii
    $s9  = "function iWibIiM(xFUk) {" fullword ascii
    $s10 = "function VEvHIBEE(gmZam,MNqRXw) {" fullword ascii
    $s11 = "if (mXEtD > 192484-817){return true;} else {return false;}" fullword ascii
    $s12 = "function lbrr(ZmYPc) {" fullword ascii
    $s13 = "if (i >= znfVt.length) {break;}" fullword ascii
    $s14 = "function yTve(opbwr) {" fullword ascii
    $s15 = "function dBvIH(HaJouF) {" fullword ascii
    $s16 = "function VoJWpzwHH(WUayVUdURIY) {" fullword ascii
    $s17 = "if(T>=V.length) {break;}" fullword ascii
    $s18 = "return xFUk.responseBody;" fullword ascii
    $s19 = "return new ActiveXObject(HaJouF);" fullword ascii
    $s20 = "function lrpN(mXEtD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}