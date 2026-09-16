rule sig_20160411_dc58cb940bb26a7db1a9fa80888ee71c {
  meta:
    description = "datamaliciousorder - file 20160411_dc58cb940bb26a7db1a9fa80888ee71c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12dce5c440b50b610166cabfbf11088ce99f88d47a05930edd6d77b56a7f645f"

  strings:
    $s1  = "var NZ = true  , sgRs = AFM[7] + AFM[9] + AFM[11];" fullword ascii
    $s2  = "return iSgVgrg[0] + iSgVgrg[2] + iSgVgrg[4] + \".F\" + iSgVgrg[7] + iSgVgrg[9] + iSgVgrg[12] + iSgVgrg[14];" fullword ascii
    $s3  = "opOC.open(zjPKE,hXvTn,false);" fullword ascii
    $s4  = "var AFM = (\"2.XMLHTTP wXdWQES GXfxa XML ream St cyeDRAId AD SwHlnqv O BSuS D\").split(\" \");" fullword ascii
    $s5  = "if (eHRGE > 157212-989){return true;} else {return false;}" fullword ascii
    $s6  = "function DqqJBBk(QLmT) {" fullword ascii
    $s7  = "function RvGjm(ncGjzm) {" fullword ascii
    $s8  = "function IWVA(bvnJd) {" fullword ascii
    $s9  = "function kPph(JcWSh,hXvTn,zjPKE) {" fullword ascii
    $s10 = "function Zqfk(VtapA,hgMjZ) {" fullword ascii
    $s11 = "function fVjF(uiPuH) {" fullword ascii
    $s12 = "function fsErq(HoMicPoy,ZOSu) {" fullword ascii
    $s13 = "function mPWLOY(EFtKHkG) {" fullword ascii
    $s14 = "return HtKsrWa;" fullword ascii
    $s15 = "bjf = O; break; " fullword ascii
    $s16 = "return Fui[WbGh[0]](hHKUr);" fullword ascii
    $s17 = "function mYBLzJ(AyEQ,pbTedm) {" fullword ascii
    $s18 = "return soJAK;" fullword ascii
    $s19 = "function DOIyZYFN(sia) {" fullword ascii
    $s20 = "return GsDPDe[QkPR[773-773]]=166-166;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}