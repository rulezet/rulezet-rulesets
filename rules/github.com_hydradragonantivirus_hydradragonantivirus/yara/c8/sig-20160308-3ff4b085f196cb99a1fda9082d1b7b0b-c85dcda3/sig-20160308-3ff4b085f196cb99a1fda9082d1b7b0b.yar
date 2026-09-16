rule sig_20160308_3ff4b085f196cb99a1fda9082d1b7b0b {
  meta:
    description = "datamaliciousorder - file 20160308_3ff4b085f196cb99a1fda9082d1b7b0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc30baf5f7d62a7f5834ad9524784aa6b34a2a3803b59023d3e334acd2fb1e44"

  strings:
    $s1  = "var LS = true  , eVTi = URF[7] + URF[9] + URF[11];" fullword ascii
    $s2  = "return zzFNNMq[0] + zzFNNMq[2] + zzFNNMq[4] + \".F\" + zzFNNMq[7] + zzFNNMq[9] + zzFNNMq[12] + zzFNNMq[14];" fullword ascii
    $s3  = "var URF = (\"2.XMLHTTP mrmrOqw brTpk XML ream St DarjouLo AD AjFUeFJ O XHUx D\").split(\" \");" fullword ascii
    $s4  = "joVkQ.open(mJJyO,RHzOS,false);" fullword ascii
    $s5  = "var zzFNNMq = \"Sc ehtenQB r VURSjXsoM ipting zXqJTfz gfh ile WLUxGHssghTIOx System nj CSMky Obj iFqFeu ect sXMklFa\".split(\" " ascii
    $s6  = "function jdByZ(DxyugO) {" fullword ascii
    $s7  = "function JQoI(qUwdH) {" fullword ascii
    $s8  = "function DRSpKcGS() {" fullword ascii
    $s9  = "function xCRm(MVrUh) {" fullword ascii
    $s10 = "function FMpI(dbYlY) {" fullword ascii
    $s11 = "return qUwdH.status;" fullword ascii
    $s12 = "function ntPp(GBSmV) {" fullword ascii
    $s13 = "return lpWnP;" fullword ascii
    $s14 = "function DsRT(RQjMe) {" fullword ascii
    $s15 = "var aUGxUmsI = \"bROo Ws hcEuWdW cri pt.S FSxGNm hell\".split(\" \");" fullword ascii
    $s16 = "function GhhE(joVkQ,RHzOS,mJJyO) {" fullword ascii
    $s17 = "if (r >= ynZSs.length) {break;}" fullword ascii
    $s18 = "function PkrE(sFqGu,NUneE) {" fullword ascii
    $s19 = "if(f>=Y.length) {break;}" fullword ascii
    $s20 = "return uROi.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}