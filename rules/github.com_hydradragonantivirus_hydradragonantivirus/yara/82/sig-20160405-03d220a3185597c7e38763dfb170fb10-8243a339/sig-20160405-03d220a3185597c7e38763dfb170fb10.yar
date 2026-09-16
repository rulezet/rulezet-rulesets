rule sig_20160405_03d220a3185597c7e38763dfb170fb10 {
  meta:
    description = "datamaliciousorder - file 20160405_03d220a3185597c7e38763dfb170fb10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2892a37bf399873562771c07121c35f48c627066ee97e572ecf97a90c99a1851"

  strings:
    $s1  = "return GfdrssU[0] + GfdrssU[2] + GfdrssU[4] + \".F\" + GfdrssU[7] + GfdrssU[9] + GfdrssU[12] + GfdrssU[14];" fullword ascii
    $s2  = "var nu = true  , eSUF = NOA[7] + NOA[9] + NOA[11];" fullword ascii
    $s3  = "AHzx.open(fMMHe,jezUx,false);" fullword ascii
    $s4  = "var NOA = (\"2.XMLHTTP ufXuYfI doSJB XML ream St PFJIpoyR AD aMptpti O mOsn D\").split(\" \");" fullword ascii
    $s5  = "function nDZiJHBU(jow) {" fullword ascii
    $s6  = "function feyzbWga(aoow) {" fullword ascii
    $s7  = "RAq = H; break; " fullword ascii
    $s8  = "function AaCy(yCnnP) {" fullword ascii
    $s9  = "function nxMyQ(HxPSNp) {" fullword ascii
    $s10 = "return qzJNAZl;" fullword ascii
    $s11 = "return SAPIF.status;" fullword ascii
    $s12 = "return GipH[NgRLXD[0]];" fullword ascii
    $s13 = "if (EQGdG == 697-497){return true;} else {return false;}" fullword ascii
    $s14 = "function jDmL(ErBBA,jezUx,fMMHe) {" fullword ascii
    $s15 = "function JZYk(EQGdG) {" fullword ascii
    $s16 = "return jow.size;" fullword ascii
    $s17 = "function GSikMP(WuJz,stKjkG) {" fullword ascii
    $s18 = "function pygx(HVahG,qUzEI) {" fullword ascii
    $s19 = "return dAZt;" fullword ascii
    $s20 = "function mxJL(YSyPV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}