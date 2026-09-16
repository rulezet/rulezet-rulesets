rule sig_20160309_baf0932185b71e827ee95ec866d9d1b2 {
  meta:
    description = "datamaliciousorder - file 20160309_baf0932185b71e827ee95ec866d9d1b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c18651a299405c46cd2c76da1bfdb57bd77994e3f1ba3759099fdddd4bd0ee2"

  strings:
    $s1  = "var kQ = true  , Cpzh = JAS[7] + JAS[9] + JAS[11];" fullword ascii
    $s2  = "return ZditkQU[0] + ZditkQU[2] + ZditkQU[4] + \".F\" + ZditkQU[7] + ZditkQU[9] + ZditkQU[12] + ZditkQU[14];" fullword ascii
    $s3  = "TSDdI.open(uqFEG,ppGjT,false);" fullword ascii
    $s4  = "var ZditkQU = \"Sc nbjhVhQ r fMxwYhcpF ipting STrBmKr FnM ile hvnFRmFIcGHdQE System yK NKPJc Obj EvbkCK ect xQHmmyS\".split(\" " ascii
    $s5  = "var JAS = (\"2.XMLHTTP LOAYlgh IRrFu XML ream St VrzWiOzP AD CwlEIov O WIWt D\").split(\" \");" fullword ascii
    $s6  = "if (v >= JwKpT.length) {break;}" fullword ascii
    $s7  = "function YFJo(ehUhH,ITCRD) {" fullword ascii
    $s8  = "function YcBL(tMcpl) {" fullword ascii
    $s9  = "function HcIx(oLSVa,uwqxS) {" fullword ascii
    $s10 = "function cyuX(TSDdI,ppGjT,uqFEG) {" fullword ascii
    $s11 = "function VMLwWwLrV(GJXcYCCLaVC) {" fullword ascii
    $s12 = "function bEuUl(JJMlNO) {" fullword ascii
    $s13 = "return RVSfJFJ(rQ,BXvfu[799-793]+BXvfu[226-219]+BXvfu[242-234]);" fullword ascii
    $s14 = "function jJcphhVLl(IHemV,eGNQs,SftSK,vSBc) {" fullword ascii
    $s15 = "function LCVp(ZmFiQ) {" fullword ascii
    $s16 = "function PnGH(JwKpT) {" fullword ascii
    $s17 = "function UAsH(iifiE) {" fullword ascii
    $s18 = "function NpIvFnv(BzeU) {" fullword ascii
    $s19 = "return new ActiveXObject(JJMlNO);" fullword ascii
    $s20 = "return BzeU.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}