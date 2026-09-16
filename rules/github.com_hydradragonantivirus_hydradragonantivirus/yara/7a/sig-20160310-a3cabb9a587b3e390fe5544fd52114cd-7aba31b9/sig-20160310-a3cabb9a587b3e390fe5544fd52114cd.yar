rule sig_20160310_a3cabb9a587b3e390fe5544fd52114cd {
  meta:
    description = "datamaliciousorder - file 20160310_a3cabb9a587b3e390fe5544fd52114cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acd3ca0d5a0821d75feb5c4e243fbccf34fb52c83b3a190de7ff5a6753b01aad"

  strings:
    $s1  = "var kS = true  , smCH = dWx[7] + dWx[9] + dWx[11];" fullword ascii
    $s2  = "return FjyGBNw[0] + FjyGBNw[2] + FjyGBNw[4] + \".F\" + FjyGBNw[7] + FjyGBNw[9] + FjyGBNw[12] + FjyGBNw[14];" fullword ascii
    $s3  = "pqMDT.open(YeQbK,Vnvqf,false);" fullword ascii
    $s4  = "var FjyGBNw = \"Sc YBvoVDz r WVEyvwELf ipting mMKsLns QVE ile VMHYgZIvAHekfL System nJ XcjSP Obj WLiBBI ect hwyQCjS\".split(\" " ascii
    $s5  = "var dWx = (\"2.XMLHTTP xVIqsJo zeraP XML ream St txfQrrsE AD ArtcfOG O KIIQ D\").split(\" \");" fullword ascii
    $s6  = "return wjYWlXh" fullword ascii
    $s7  = "function bVtj(WhMsE) {" fullword ascii
    $s8  = "if (uFHDi > 175499-999){return true;} else {return false;}" fullword ascii
    $s9  = "function cSzh(BKDuA) {" fullword ascii
    $s10 = "if(G>=N.length) {break;}" fullword ascii
    $s11 = "function pNpPYcTi() {" fullword ascii
    $s12 = "return NMOT.responseBody;" fullword ascii
    $s13 = "function pPRXGXlop(YBhKPPysAFB) {" fullword ascii
    $s14 = "return vWtspa.position=828-828;" fullword ascii
    $s15 = "function fPOBpRf(NMOT) {" fullword ascii
    $s16 = "return new ActiveXObject(BlKgAn);" fullword ascii
    $s17 = "return rxsn.ExpandEnvironmentStrings(VvjCu);" fullword ascii
    $s18 = "function WJCJt(BlKgAn) {" fullword ascii
    $s19 = "function QBGDQRRd(Zhd) {" fullword ascii
    $s20 = "function hVaQJci(rxsn,VvjCu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}