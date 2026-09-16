rule sig_20160411_bebfe2c7862807f2dde4a9a67f81b4d2 {
  meta:
    description = "datamaliciousorder - file 20160411_bebfe2c7862807f2dde4a9a67f81b4d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72550ad22bfa45c978375eb7fa27eb05d1fffc2da4d74837029fb2193d456f60"

  strings:
    $s1  = "var It = true  , ZXPi = LSh[7] + LSh[9] + LSh[11];" fullword ascii
    $s2  = "return CMBaOrq[0] + CMBaOrq[2] + CMBaOrq[4] + \".F\" + CMBaOrq[7] + CMBaOrq[9] + CMBaOrq[12] + CMBaOrq[14];" fullword ascii
    $s3  = "var LSh = (\"2.XMLHTTP draWIsX KWhTJ XML ream St QEIitoqc AD GAUnduu O gdhI D\").split(\" \");" fullword ascii
    $s4  = "bzeC.open(jYGze,Tltvm,false);" fullword ascii
    $s5  = "if(C>=s.length) {break;}" fullword ascii
    $s6  = "return XHiZ[esQbSAS[0]+esQbSAS[1]];" fullword ascii
    $s7  = "return lBOMmCX[0];" fullword ascii
    $s8  = "function bXsmoG(YKYj,HJHgdb) {" fullword ascii
    $s9  = "return VIXEvET(Sf,pnDojb+wOgYs[301-293]);" fullword ascii
    $s10 = "return ycvAJnn;" fullword ascii
    $s11 = "if (yUnwQ == 312-112){return true;} else {return false;}" fullword ascii
    $s12 = "function WLzN(OPxrA) {" fullword ascii
    $s13 = "function FPDmKZto(heGH) {" fullword ascii
    $s14 = "function vSoOvq(kXvTrPv) {" fullword ascii
    $s15 = "function wScy(wppRp) {" fullword ascii
    $s16 = "function CXEn(JXwdp) {" fullword ascii
    $s17 = "function TaJkd(FMkHllfZ,PgTK) {" fullword ascii
    $s18 = "return rBkbXC[yBiP[110-110]]=752-752;" fullword ascii
    $s19 = "function epZu(bpeTK,zwFPn) {" fullword ascii
    $s20 = "function xOzQ(yUnwQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}