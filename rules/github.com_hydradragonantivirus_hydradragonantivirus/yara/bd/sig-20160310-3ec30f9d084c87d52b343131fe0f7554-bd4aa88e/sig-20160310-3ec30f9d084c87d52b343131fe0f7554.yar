rule sig_20160310_3ec30f9d084c87d52b343131fe0f7554 {
  meta:
    description = "datamaliciousorder - file 20160310_3ec30f9d084c87d52b343131fe0f7554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c47d512af0df3b1815c145168b1aebe34053f9a3876692e0bb314920076a0c"

  strings:
    $s1  = "var eb = true  , uKyX = PsQ[7] + PsQ[9] + PsQ[11];" fullword ascii
    $s2  = "return uCYeckB[0] + uCYeckB[2] + uCYeckB[4] + \".F\" + uCYeckB[7] + uCYeckB[9] + uCYeckB[12] + uCYeckB[14];" fullword ascii
    $s3  = "Nuklv.open(ZLBWD,YUVAb,false);" fullword ascii
    $s4  = "var PsQ = (\"2.XMLHTTP KTDzter UEJyV XML ream St ENKZHYVq AD eqdQroK O dycM D\").split(\" \");" fullword ascii
    $s5  = "var uCYeckB = \"Sc OHEUOyo r WqXrPJjbz ipting tJnByTd sqS ile xuaqSpelrbYbBs System oA ZbJGp Obj yDpSrb ect ecCrpkk\".split(\" " ascii
    $s6  = "function KwaiosITh(csGlP,JJLaz,QWUYF,fQDt) {" fullword ascii
    $s7  = "function moKoQizuC(sUQUfQgOTvU) {" fullword ascii
    $s8  = "function fVsU(VUKYN) {" fullword ascii
    $s9  = "return vtpHRuF(XA,pJLrh[937-931]+pJLrh[492-485]+pJLrh[874-866]);" fullword ascii
    $s10 = "function dgZo(snPZZ) {" fullword ascii
    $s11 = "return cpEFQhs" fullword ascii
    $s12 = "return gwDohk.position=835-835;" fullword ascii
    $s13 = "function GEdQ(BHPtD,DoBAV) {" fullword ascii
    $s14 = "if(g>=r.length) {break;}" fullword ascii
    $s15 = "if (M >= snPZZ.length) {break;}" fullword ascii
    $s16 = "function VqPH(yDPGk) {" fullword ascii
    $s17 = "return bnh.size;" fullword ascii
    $s18 = "function fFZtCGbc() {" fullword ascii
    $s19 = "function XcfmmnY(LAce) {" fullword ascii
    $s20 = "return new ActiveXObject(xVTlYc);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}