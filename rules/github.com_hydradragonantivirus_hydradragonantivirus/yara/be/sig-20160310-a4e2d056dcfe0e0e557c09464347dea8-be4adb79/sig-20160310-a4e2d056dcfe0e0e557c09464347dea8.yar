rule sig_20160310_a4e2d056dcfe0e0e557c09464347dea8 {
  meta:
    description = "datamaliciousorder - file 20160310_a4e2d056dcfe0e0e557c09464347dea8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "507c38557b1fb3d282ab530ec6a02f514bbf3effce6459c62b7ab0a9d10e4dc3"

  strings:
    $s1  = "return kMAxkSO[0] + kMAxkSO[2] + kMAxkSO[4] + \".F\" + kMAxkSO[7] + kMAxkSO[9] + kMAxkSO[12] + kMAxkSO[14];" fullword ascii
    $s2  = "var Vk = true  , ARXf = GYx[7] + GYx[9] + GYx[11];" fullword ascii
    $s3  = "eNdhD.open(ErISG,fmzDb,false);" fullword ascii
    $s4  = "var GYx = (\"2.XMLHTTP scivcVV RDruT XML ream St VKcSjHsP AD VFUSihO O AGia D\").split(\" \");" fullword ascii
    $s5  = "var kMAxkSO = \"Sc nlLoqDQ r yGCdKIsuX ipting ICTqjvn jlP ile cDbNkPAzQHtWlr System bx whhSG Obj hjyFZz ect vLhAByu\".split(\" " ascii
    $s6  = "if (P >= DnWFi.length) {break;}" fullword ascii
    $s7  = "function BoNK(tsGSv) {" fullword ascii
    $s8  = "function ZVAx(DnWFi) {" fullword ascii
    $s9  = "jfw = a; break; " fullword ascii
    $s10 = "function llMVEgY(zRcx) {" fullword ascii
    $s11 = "function iGPl(XNLOm,qRZiX) {" fullword ascii
    $s12 = "function zcSHUdWx(tRu) {" fullword ascii
    $s13 = "return Sheh.ExpandEnvironmentStrings(fWChe);" fullword ascii
    $s14 = "return ftJAeRN" fullword ascii
    $s15 = "function aTkhinHkQ(pJptvGYJKJK) {" fullword ascii
    $s16 = "function Gews(LRFpD) {" fullword ascii
    $s17 = "function wGgU(eNdhD,fmzDb,ErISG) {" fullword ascii
    $s18 = "BoNK(wOr); wOr.type = 1; ajpi(wOr,llMVEgY(yO)); if (Gews(zcSHUdWx(wOr)))  {" fullword ascii
    $s19 = "function XgDejOs(Sheh,fWChe) {" fullword ascii
    $s20 = "function ajpi(opTJi,fymrk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}