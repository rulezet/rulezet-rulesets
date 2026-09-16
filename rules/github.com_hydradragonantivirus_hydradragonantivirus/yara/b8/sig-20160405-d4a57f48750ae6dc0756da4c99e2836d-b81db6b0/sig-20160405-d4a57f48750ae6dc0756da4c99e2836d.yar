rule sig_20160405_d4a57f48750ae6dc0756da4c99e2836d {
  meta:
    description = "datamaliciousorder - file 20160405_d4a57f48750ae6dc0756da4c99e2836d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa03cd2435bb17f6dd24ea2117f817fca2086d9d1d41c22c6ac9c4418d9cbfc"

  strings:
    $s1  = "var Dh = true  , mDbY = erA[7] + erA[9] + erA[11];" fullword ascii
    $s2  = "return grdemvD[0] + grdemvD[2] + grdemvD[4] + \".F\" + grdemvD[7] + grdemvD[9] + grdemvD[12] + grdemvD[14];" fullword ascii
    $s3  = "var erA = (\"2.XMLHTTP mlAigDQ CSYuK XML ream St SZzOKMdK AD GKpuouZ O SuMu D\").split(\" \");" fullword ascii
    $s4  = "OQbr.open(exFcW,Iliwk,false);" fullword ascii
    $s5  = "return cGiz;" fullword ascii
    $s6  = "return sXh.size;" fullword ascii
    $s7  = "return new ActiveXObject(MaBl);" fullword ascii
    $s8  = "function rZtC(oePec) {" fullword ascii
    $s9  = "function qucIIf(WXtu,SghPqS) {" fullword ascii
    $s10 = "return zsrfm;" fullword ascii
    $s11 = "function MolB(lOpzj) {" fullword ascii
    $s12 = "function kQnJ(KNKDj,pLxRd) {" fullword ascii
    $s13 = "if (oIMGI == 655-455){return true;} else {return false;}" fullword ascii
    $s14 = "function GzaSc(Led,OvtSZ) {" fullword ascii
    $s15 = "return Led.split(OvtSZ);" fullword ascii
    $s16 = "function eoHRvM(MViVfHd) {" fullword ascii
    $s17 = "function ftsHJ(zZuKVv) {" fullword ascii
    $s18 = "function bqgT(YrevG,jZpAo) {" fullword ascii
    $s19 = "return odQdYJO[0];" fullword ascii
    $s20 = "return ABgp[HUiAZm[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}