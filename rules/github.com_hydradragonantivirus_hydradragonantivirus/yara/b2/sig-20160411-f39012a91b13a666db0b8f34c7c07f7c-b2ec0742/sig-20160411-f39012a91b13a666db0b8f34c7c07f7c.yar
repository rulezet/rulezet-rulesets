rule sig_20160411_f39012a91b13a666db0b8f34c7c07f7c {
  meta:
    description = "datamaliciousorder - file 20160411_f39012a91b13a666db0b8f34c7c07f7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70e8effcf65b866f0135140654b1b84f032819229732c563fe8e3212366b2b15"

  strings:
    $s1  = "return lOGiEW[oXLS[786-786]]=933-933;" fullword ascii
    $s2  = "function alQDO(lOGiEW) {" fullword ascii
    $s3  = "var jo = true  , NfTO = lRy[7] + lRy[9] + lRy[11];" fullword ascii
    $s4  = "return ICzsQcp[0] + ICzsQcp[2] + ICzsQcp[4] + \".F\" + ICzsQcp[7] + ICzsQcp[9] + ICzsQcp[12] + ICzsQcp[14];" fullword ascii
    $s5  = "var lRy = (\"2.XMLHTTP JHrtHfx iABic XML ream St bLosEhvb AD FaDvBuj O OeGX D\").split(\" \");" fullword ascii
    $s6  = "UogM.open(qDAKt,llLmL,false);" fullword ascii
    $s7  = "function ZSBL(NxGWd) {" fullword ascii
    $s8  = "function QbDMoE(WAlF,ENjJES) {" fullword ascii
    $s9  = "function bJEE(sHBpi,llLmL,qDAKt) {" fullword ascii
    $s10 = "function nFZaM(bbgaKszx,Xvte) {" fullword ascii
    $s11 = "function GYwFQlDC(ccE) {" fullword ascii
    $s12 = "function riHe(ASDZq,tuxpd) {" fullword ascii
    $s13 = "function gLda(tydgq) {" fullword ascii
    $s14 = "function zwrL(NcGlR) {" fullword ascii
    $s15 = "function xPKiCCgQ(qlxM) {" fullword ascii
    $s16 = "return pqZPl;" fullword ascii
    $s17 = "function LxYX(YQKCz) {" fullword ascii
    $s18 = "return xGlnMZJ;" fullword ascii
    $s19 = "if (tydgq > 164657-557){return true;} else {return false;}" fullword ascii
    $s20 = "function pRidvCZPq(cVRcq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}