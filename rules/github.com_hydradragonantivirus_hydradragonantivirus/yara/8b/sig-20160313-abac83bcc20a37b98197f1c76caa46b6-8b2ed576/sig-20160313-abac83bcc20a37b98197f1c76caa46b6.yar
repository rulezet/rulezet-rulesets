rule sig_20160313_abac83bcc20a37b98197f1c76caa46b6 {
  meta:
    description = "datamaliciousorder - file 20160313_abac83bcc20a37b98197f1c76caa46b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93d6275fa7e76e19ff0e3218c351f946c3705158978ddf3166987c2171861d6c"

  strings:
    $s1  = "return xOQgSAg[0] + xOQgSAg[2] + xOQgSAg[4] + \".F\" + xOQgSAg[7] + xOQgSAg[9] + xOQgSAg[12] + xOQgSAg[14];" fullword ascii
    $s2  = "var Qv = true  , pdaw = yfK[7] + yfK[9] + yfK[11];" fullword ascii
    $s3  = "VuwsD.open(VFgoT,YhDSH,false);" fullword ascii
    $s4  = "var yfK = (\"2.XMLHTTP gERDDqc LmpqU XML ream St hfAVVuAj AD NLNzrtX O KVKe D\").split(\" \");" fullword ascii
    $s5  = "var xOQgSAg = \"Sc VAwiSqw r YjbDwvzAX ipting VCOiKKe BOv ile FAPkNoUWAcdyvd System gh vhkhR Obj iJlsUp ect UxdLEoN\".split(\" " ascii
    $s6  = "function IGkn(OAQNx) {" fullword ascii
    $s7  = "function vJrzudnK(NEc) {" fullword ascii
    $s8  = "function IXXwdST(TPpp,xlKWL) {" fullword ascii
    $s9  = "return oBbZJE.position=961-961;" fullword ascii
    $s10 = "function SmvHdWU(Fiwl) {" fullword ascii
    $s11 = "return bTtSG;" fullword ascii
    $s12 = "function VTOG(RvtIV) {" fullword ascii
    $s13 = "function fqSX(sgmWs) {" fullword ascii
    $s14 = "function YqLb(JUKzZ,UOIAw) {" fullword ascii
    $s15 = "function vcCJy(NQMLYV) {" fullword ascii
    $s16 = "function ZNvH(EFiDW) {" fullword ascii
    $s17 = "return NEc.size;" fullword ascii
    $s18 = "RAk = L; break; " fullword ascii
    $s19 = "return RvtIV.status;" fullword ascii
    $s20 = "function wGTIg(oBbZJE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}