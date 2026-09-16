rule sig_20160310_86d22f0543bcc3f8ab551bb5acb22b2b {
  meta:
    description = "datamaliciousorder - file 20160310_86d22f0543bcc3f8ab551bb5acb22b2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfc0781d7a0c4b542847adab45a6e4a31dbb91fcd2cfbec0e995cb370a36f6d6"

  strings:
    $s1  = "return tVdBhgN[0] + tVdBhgN[2] + tVdBhgN[4] + \".F\" + tVdBhgN[7] + tVdBhgN[9] + tVdBhgN[12] + tVdBhgN[14];" fullword ascii
    $s2  = "var Oh = true  , BaPP = CZy[7] + CZy[9] + CZy[11];" fullword ascii
    $s3  = "iZVHq.open(qUjUB,ilRey,false);" fullword ascii
    $s4  = "var CZy = (\"2.XMLHTTP nfbYjvx zyWQm XML ream St OuxlkAuo AD jEqdjFT O nHre D\").split(\" \");" fullword ascii
    $s5  = "var tVdBhgN = \"Sc FjVrvro r ieVfDoRKf ipting wTVrgPl zWb ile QMOusLBXLwAeRd System RY okpRb Obj KFBiKK ect BKfayEm\".split(\" " ascii
    $s6  = "return YpRNOQu" fullword ascii
    $s7  = "function FsEA(bwjoU) {" fullword ascii
    $s8  = "return GXCn.responseBody;" fullword ascii
    $s9  = "function CEMJqxvxd(akIvU,BVzgh,PTQba,znvV) {" fullword ascii
    $s10 = "function jFTcoJFC() {" fullword ascii
    $s11 = "if (x >= qYZhw.length) {break;}" fullword ascii
    $s12 = "function YOzyZbuCS(OyiLOpFBEvf) {" fullword ascii
    $s13 = "var Ox = Jute(oQ).split(\" \");" fullword ascii
    $s14 = "if(M>=A.length) {break;}" fullword ascii
    $s15 = "return wTHAwp.position=623-623;" fullword ascii
    $s16 = "function eHJZK(uqKYHk) {" fullword ascii
    $s17 = "function peBu(DgQjD) {" fullword ascii
    $s18 = "function aAzF(ddosp) {" fullword ascii
    $s19 = "return UYRq.ExpandEnvironmentStrings(RZTkM);" fullword ascii
    $s20 = "function oQLG(MEmiE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}