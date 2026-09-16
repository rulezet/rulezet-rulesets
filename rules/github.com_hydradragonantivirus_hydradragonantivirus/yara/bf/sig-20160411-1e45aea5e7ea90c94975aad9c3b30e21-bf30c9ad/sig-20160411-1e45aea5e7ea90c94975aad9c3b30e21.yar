rule sig_20160411_1e45aea5e7ea90c94975aad9c3b30e21 {
  meta:
    description = "datamaliciousorder - file 20160411_1e45aea5e7ea90c94975aad9c3b30e21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f57fa44e3629faa1f7c78cae7f73b3af38a4f3633831bb31e81b89d1a7716a0"

  strings:
    $s1  = "var Ix = true  , KtOO = AaF[7] + AaF[9] + AaF[11];" fullword ascii
    $s2  = "return HTcyAyE[0] + HTcyAyE[2] + HTcyAyE[4] + \".F\" + HTcyAyE[7] + HTcyAyE[9] + HTcyAyE[12] + HTcyAyE[14];" fullword ascii
    $s3  = "jmXw.open(bKwoh,CGFbl,false);" fullword ascii
    $s4  = "var AaF = (\"2.XMLHTTP xBwCqdY whuQy XML ream St ksmauEcE AD NQJOvzK O QwIL D\").split(\" \");" fullword ascii
    $s5  = "if(X>=J.length) {break;}" fullword ascii
    $s6  = "function YFsi(PyYMO) {" fullword ascii
    $s7  = "function ejAHF(XGrLHD) {" fullword ascii
    $s8  = "function ugUytka(EYKw) {" fullword ascii
    $s9  = "function qvVtBMKO(YuK) {" fullword ascii
    $s10 = "function iHCO(Yyfcu) {" fullword ascii
    $s11 = "sAe = X; break; " fullword ascii
    $s12 = "function BRyI(jnNbD) {" fullword ascii
    $s13 = "return wgAZnaD[0];" fullword ascii
    $s14 = "function Xysjp(EPAunN) {" fullword ascii
    $s15 = "function lgqZI(SxFqeoWr,ymxF) {" fullword ascii
    $s16 = "function IyXBdzbMK(VvJmMGUIeJD) {" fullword ascii
    $s17 = "function Jcln(ZlPlY,PktUR) {" fullword ascii
    $s18 = "function oRYx(HuUMY) {" fullword ascii
    $s19 = "if (PyYMO > 174286-857){return true;} else {return false;}" fullword ascii
    $s20 = "return YuK.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}