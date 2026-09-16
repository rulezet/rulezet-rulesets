rule sig_20160321_353373278dc9bbf9fc34b77f0d2eb1a7 {
  meta:
    description = "datamaliciousorder - file 20160321_353373278dc9bbf9fc34b77f0d2eb1a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ba7e4238d05be55632830b421b7d28aca32b66940a0d0739ebc535f940ad053"

  strings:
    $s1  = "return WScript.CreateObject(oLZZi);" fullword ascii
    $s2  = "var UT = true  , unAx = cTx[7] + cTx[9] + cTx[11];" fullword ascii
    $s3  = "return KSxMmut[0] + KSxMmut[2] + KSxMmut[4] + \".F\" + KSxMmut[7] + KSxMmut[9] + KSxMmut[12] + KSxMmut[14];" fullword ascii
    $s4  = "mYAkh.open(RTLqK,aIyLM,false);" fullword ascii
    $s5  = "var KSxMmut = OpJfD(odJVotnAZq+\" \"+\"System RH ZHqUt Obj OsBPQo ect ZoxhGxa bfpsp\", \" \");" fullword ascii
    $s6  = "var cTx = (\"2.XMLHTTP lgCsNoK CNdhf XML ream St GFvqjvYW AD sXBqgJl O busy D\").split(\" \");" fullword ascii
    $s7  = "return JvDp.ExpandEnvironmentStrings(sxOKo);" fullword ascii
    $s8  = "function hGMLqXa(WLST) {" fullword ascii
    $s9  = "function bsZjMHgfm(JcNasVhmPFZ) {" fullword ascii
    $s10 = "function UlyQ(qcgCN,QuOcZ) {" fullword ascii
    $s11 = "function BqsTcRTn(RDD) {" fullword ascii
    $s12 = "return xstATg.position=120-120;" fullword ascii
    $s13 = "function WrJfsFR(JvDp,sxOKo) {" fullword ascii
    $s14 = "function OOgo(lQrAq) {" fullword ascii
    $s15 = "function sRBV(mYAkh,aIyLM,RTLqK) {" fullword ascii
    $s16 = "function LpCz(kaLRs) {" fullword ascii
    $s17 = "if(v>=i.length) {break;}" fullword ascii
    $s18 = "function IHEYl(OgEHNl) {" fullword ascii
    $s19 = "function kLIH(RBjrX) {" fullword ascii
    $s20 = "function CRHPCvQnu(GrMqt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}