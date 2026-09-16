rule sig_20160308_1f725a26cff5d8ae25d4d6450a30a2b7 {
  meta:
    description = "datamaliciousorder - file 20160308_1f725a26cff5d8ae25d4d6450a30a2b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f2747516259df6d0b7aeda6cbd0a9ef2b7bc3001c19d180787be1f3315fe2cd"

  strings:
    $s1  = "return FFKlxft[0] + FFKlxft[2] + FFKlxft[4] + \".F\" + FFKlxft[7] + FFKlxft[9] + FFKlxft[12] + FFKlxft[14];" fullword ascii
    $s2  = "var SF = true  , mSKV = XHX[7] + XHX[9] + XHX[11];" fullword ascii
    $s3  = "var FFKlxft = \"Sc BSnJAYK r ZNXcCWFlb ipting GjxatuE YtD ile oomctxDjJJodlK System uD cXCzV Obj YRNWuf ect kqkpUox\".split(\" " ascii
    $s4  = "oDEcY.open(kmwwW,BDICk,false);" fullword ascii
    $s5  = "var XHX = (\"2.XMLHTTP hvNnyfW unfrt XML ream St ordcpsqG AD KgttYnR O ANmk D\").split(\" \");" fullword ascii
    $s6  = "if(G>=W.length) {break;}" fullword ascii
    $s7  = "function uJMUMOQg(UrZ) {" fullword ascii
    $s8  = "return LwLMf;" fullword ascii
    $s9  = "return ErMk.responseBody;" fullword ascii
    $s10 = "function xXiy(HBehy) {" fullword ascii
    $s11 = "function KKYk(knPTE,gqDsI) {" fullword ascii
    $s12 = "function LqKk(QOCIo,jTgpV) {" fullword ascii
    $s13 = "function LsNWESXJQ(MqaUQvVMjHO) {" fullword ascii
    $s14 = "function cBNm(rGKcN) {" fullword ascii
    $s15 = "function GaajHoWS() {" fullword ascii
    $s16 = "function sgoX(TiXyX) {" fullword ascii
    $s17 = "function ojkg(oDEcY,BDICk,kmwwW) {" fullword ascii
    $s18 = "if (J >= HBehy.length) {break;}" fullword ascii
    $s19 = "if (((new Date())>0,7855730888)) {" fullword ascii
    $s20 = "function LdBxUkV(ErMk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}