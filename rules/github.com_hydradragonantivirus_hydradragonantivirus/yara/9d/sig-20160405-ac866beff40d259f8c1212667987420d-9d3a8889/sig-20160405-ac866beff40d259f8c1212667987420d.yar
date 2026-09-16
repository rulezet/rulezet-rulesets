rule sig_20160405_ac866beff40d259f8c1212667987420d {
  meta:
    description = "datamaliciousorder - file 20160405_ac866beff40d259f8c1212667987420d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "803429eb576bba13bb1fc678ad23628a73c7e39154e81d36b0aa5b2afe3adfd3"

  strings:
    $s1  = "return PuzgbJU[0] + PuzgbJU[2] + PuzgbJU[4] + \".F\" + PuzgbJU[7] + PuzgbJU[9] + PuzgbJU[12] + PuzgbJU[14];" fullword ascii
    $s2  = "var aW = true  , XKYx = Blf[7] + Blf[9] + Blf[11];" fullword ascii
    $s3  = "var Blf = (\"2.XMLHTTP CKqlWcK foDfq XML ream St xkpkTxxR AD bwFAxFc O Rkak D\").split(\" \");" fullword ascii
    $s4  = "rjqi.open(QLbcE,IOdWA,false);" fullword ascii
    $s5  = "function DjllXEPK(jzQa) {" fullword ascii
    $s6  = "function rSEi(NzcYs,rLYbH) {" fullword ascii
    $s7  = "if (BdGXC == 445-245){return true;} else {return false;}" fullword ascii
    $s8  = "return tejdJRi(Nz,rUpOl[991-985]+rUpOl[427-420]+rUpOl[410-402]);" fullword ascii
    $s9  = "if (dgjSg > 160770-715){return true;} else {return false;}" fullword ascii
    $s10 = "function NqxL(Rqgtc) {" fullword ascii
    $s11 = "function qNlzoixmV(dxges) {" fullword ascii
    $s12 = "function BjKd(AJFpb) {" fullword ascii
    $s13 = "function aXCru(Uhiogj) {" fullword ascii
    $s14 = "return hlW.split(EjvUx);" fullword ascii
    $s15 = "function vmcI(BVdCd,IOdWA,QLbcE) {" fullword ascii
    $s16 = "zVs = Z; break; " fullword ascii
    $s17 = "return sbvT[ChBmVL[0]];" fullword ascii
    $s18 = "return bHh.size;" fullword ascii
    $s19 = "function gtFBUDc(sbvT) {" fullword ascii
    $s20 = "return mIpak;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}