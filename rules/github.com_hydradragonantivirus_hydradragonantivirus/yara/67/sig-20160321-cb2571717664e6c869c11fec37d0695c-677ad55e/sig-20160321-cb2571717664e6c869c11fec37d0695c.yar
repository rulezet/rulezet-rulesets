rule sig_20160321_cb2571717664e6c869c11fec37d0695c {
  meta:
    description = "datamaliciousorder - file 20160321_cb2571717664e6c869c11fec37d0695c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51b0facc9f5f80556bf28e8ef91a582f72bc8736df45a5442911a1710a5a35c9"

  strings:
    $s1  = "return WScript.CreateObject(ZFhuE);" fullword ascii
    $s2  = "var jL = true  , dlkd = tDt[7] + tDt[9] + tDt[11];" fullword ascii
    $s3  = "return IKWRXIW[0] + IKWRXIW[2] + IKWRXIW[4] + \".F\" + IKWRXIW[7] + IKWRXIW[9] + IKWRXIW[12] + IKWRXIW[14];" fullword ascii
    $s4  = "JFlWN.open(bHyhN,QqGmp,false);" fullword ascii
    $s5  = "var IKWRXIW = BObxA(HhxBDAKhRS+\" \"+\"System KT TXgnS Obj wkmTeu ect ggwIRru kwFma\", \" \");" fullword ascii
    $s6  = "var tDt = (\"2.XMLHTTP HNiwFfk QWZnV XML ream St mzvnBAlN AD MJMVLSE O RNMN D\").split(\" \");" fullword ascii
    $s7  = "if(N>=R.length) {break;}" fullword ascii
    $s8  = "function Xdho(lFNOq) {" fullword ascii
    $s9  = "Kzi = N; break; " fullword ascii
    $s10 = "function BOrA(JFlWN,QqGmp,bHyhN) {" fullword ascii
    $s11 = "function GWsbFrz(oiqo) {" fullword ascii
    $s12 = "return kwv.split(mDprb);" fullword ascii
    $s13 = "function eWaX(UuFmW) {" fullword ascii
    $s14 = "return Byo.size;" fullword ascii
    $s15 = "function emwWE(Cxryso) {" fullword ascii
    $s16 = "function cPLJAAK(xjwu,OoZiv) {" fullword ascii
    $s17 = "BOrA(kQ,CdhYM+R[N]+x, nGS[12]+nGS[14]+nGS[16]); vxfh(kQ); " fullword ascii
    $s18 = "function YhUUDYSrD(RTRXd) {" fullword ascii
    $s19 = "return PpobR;" fullword ascii
    $s20 = "function GHPt(ZFhuE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}