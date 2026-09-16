rule sig_20160314_6e02316a68b330c37037cc4c852d73c7 {
  meta:
    description = "datamaliciousorder - file 20160314_6e02316a68b330c37037cc4c852d73c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8bdeb03da8ab5d3d9f9e73a7506db000d11339452411f162493a211156a2e1c"

  strings:
    $s1  = "return EEXFmtZ[0] + EEXFmtZ[2] + EEXFmtZ[4] + \".F\" + EEXFmtZ[7] + EEXFmtZ[9] + EEXFmtZ[12] + EEXFmtZ[14];" fullword ascii
    $s2  = "var zD = true  , QXBN = aiZ[7] + aiZ[9] + aiZ[11];" fullword ascii
    $s3  = "var EEXFmtZ = \"Sc lCNmedP r joTKpqnrX ipting IuhLrEF nOL ile UlOLQTlxVDndZL System ja PuaPj Obj nxKKZl ect NtTeLix aNRAC\".spli" ascii
    $s4  = "var EEXFmtZ = \"Sc lCNmedP r joTKpqnrX ipting IuhLrEF nOL ile UlOLQTlxVDndZL System ja PuaPj Obj nxKKZl ect NtTeLix aNRAC\".spli" ascii
    $s5  = "var aiZ = (\"2.XMLHTTP JqLqxHz NYwHa XML ream St mPYKbsBO AD EgjWzlH O IMLf D\").split(\" \");" fullword ascii
    $s6  = "joUIT.open(KbqCx,nbQQa,false);" fullword ascii
    $s7  = "function HafmW(Kdcgyp) {" fullword ascii
    $s8  = "return ZCwWZDX(mn,Mkmrz[648-642]+Mkmrz[652-645]+Mkmrz[205-197]);" fullword ascii
    $s9  = "function Rgho(oMAQn) {" fullword ascii
    $s10 = "if (n >= SPDaV.length) {break;}" fullword ascii
    $s11 = "function CwfU(zxQGl) {" fullword ascii
    $s12 = "return new ActiveXObject(thtpJC);" fullword ascii
    $s13 = "return Kdcgyp.position=311-311;" fullword ascii
    $s14 = "function GOOi(joUIT,nbQQa,KbqCx) {" fullword ascii
    $s15 = "function ZCwWZDX(Zdrq,LdBMu) {" fullword ascii
    $s16 = "function oynB(PjgEW) {" fullword ascii
    $s17 = "function mHTUjysi() {" fullword ascii
    $s18 = "return IHj.size;" fullword ascii
    $s19 = "function BfCLfuXxa(gViZZIIRwRC) {" fullword ascii
    $s20 = "function jDka(IaGIZ,XOiey) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}