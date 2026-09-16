rule sig_20160315_0f0b904689872ec19807b489f6d6e386 {
  meta:
    description = "datamaliciousorder - file 20160315_0f0b904689872ec19807b489f6d6e386.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d3047e6d37fd1dd01c961c2ada77d45d7d052ef31340b3eaec3076de6255568"

  strings:
    $s1  = "var KK = true  , xtcy = Qqa[7] + Qqa[9] + Qqa[11];" fullword ascii
    $s2  = "return tyBpGfx[0] + tyBpGfx[2] + tyBpGfx[4] + \".F\" + tyBpGfx[7] + tyBpGfx[9] + tyBpGfx[12] + tyBpGfx[14];" fullword ascii
    $s3  = "var tyBpGfx = uFSDu(\"Sc NEJqWal r rirSQPAZC ipting abSaEqp Sgu ile hsqmYWWSuzDfcC System KT cdYgl Obj VuERLs ect KhpdxHi xXcEW" ascii
    $s4  = "var Qqa = (\"2.XMLHTTP xRFInae QDyNX XML ream St OyXlGlyI AD mGSrRML O GfqG D\").split(\" \");" fullword ascii
    $s5  = "RSGMe.open(DcjSY,LfoBP,false);" fullword ascii
    $s6  = "var tyBpGfx = uFSDu(\"Sc NEJqWal r rirSQPAZC ipting abSaEqp Sgu ile hsqmYWWSuzDfcC System KT cdYgl Obj VuERLs ect KhpdxHi xXcEW" ascii
    $s7  = "return revaazu" fullword ascii
    $s8  = "if(o>=I.length) {break;}" fullword ascii
    $s9  = "function KKzf(RSGMe,LfoBP,DcjSY) {" fullword ascii
    $s10 = "function gabv(oapZH) {" fullword ascii
    $s11 = "function SUtVzeqh(BNG) {" fullword ascii
    $s12 = "function XuJx(jwuWG,oTyOz) {" fullword ascii
    $s13 = "return aCLH.responseBody;" fullword ascii
    $s14 = "if (oapZH > 197602-822){return true;} else {return false;}" fullword ascii
    $s15 = "if (B >= meRBd.length) {break;}" fullword ascii
    $s16 = "return DwWPPA.position=495-495;" fullword ascii
    $s17 = "return TQOdq.status;" fullword ascii
    $s18 = "function uFSDu(pfE,AdKHr) {" fullword ascii
    $s19 = "return Mwqg.ExpandEnvironmentStrings(FVHvX);" fullword ascii
    $s20 = "function RgXq(BbHAY,vwweU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}