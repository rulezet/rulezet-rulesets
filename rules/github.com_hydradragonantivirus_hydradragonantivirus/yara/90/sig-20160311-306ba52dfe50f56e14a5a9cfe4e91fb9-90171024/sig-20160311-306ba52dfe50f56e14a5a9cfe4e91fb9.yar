rule sig_20160311_306ba52dfe50f56e14a5a9cfe4e91fb9 {
  meta:
    description = "datamaliciousorder - file 20160311_306ba52dfe50f56e14a5a9cfe4e91fb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90485702fd43bdb82c8a9d971bc7c8762e12646f1941dfe9d59ccc8e9d64340d"

  strings:
    $s1  = "var KM = true  , Zutj = mju[7] + mju[9] + mju[11];" fullword ascii
    $s2  = "return vEQJrrc[0] + vEQJrrc[2] + vEQJrrc[4] + \".F\" + vEQJrrc[7] + vEQJrrc[9] + vEQJrrc[12] + vEQJrrc[14];" fullword ascii
    $s3  = "var vEQJrrc = \"Sc xPxfMeK r xpoEIHktL ipting wDaEytU wQG ile ptQdBaFqDOwGYj System wW NAtsg Obj CcPNdz ect NAITeiJ\".split(\" " ascii
    $s4  = "var mju = (\"2.XMLHTTP ZUPxoAV WrTSn XML ream St kJAqjvFR AD VwjiAmd O Ryya D\").split(\" \");" fullword ascii
    $s5  = "uoKZH.open(OQhqv,qxWnZ,false);" fullword ascii
    $s6  = "return new ActiveXObject(GbCWai);" fullword ascii
    $s7  = "return epJtT.status;" fullword ascii
    $s8  = "return tyeU.ExpandEnvironmentStrings(MnyiR);" fullword ascii
    $s9  = "function SzAr(armPZ,sxNYS) {" fullword ascii
    $s10 = "if (J >= Xsjki.length) {break;}" fullword ascii
    $s11 = "return aCFrd;" fullword ascii
    $s12 = "return VIQPtX.position=657-657;" fullword ascii
    $s13 = "function UGwL(uoKZH,qxWnZ,OQhqv) {" fullword ascii
    $s14 = "function eugQ(qPHMv) {" fullword ascii
    $s15 = "Qya = D; break; " fullword ascii
    $s16 = "function erWzi(GbCWai) {" fullword ascii
    $s17 = "function ypNGyjLo(mBk) {" fullword ascii
    $s18 = "function QpJWOKl(tyeU,MnyiR) {" fullword ascii
    $s19 = "function rdSuXPfQz(zRJcsIhzisN) {" fullword ascii
    $s20 = "function zHQEGxFz() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}