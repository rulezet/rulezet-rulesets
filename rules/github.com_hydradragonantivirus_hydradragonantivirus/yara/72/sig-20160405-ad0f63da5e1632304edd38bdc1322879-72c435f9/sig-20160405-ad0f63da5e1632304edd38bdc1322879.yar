rule sig_20160405_ad0f63da5e1632304edd38bdc1322879 {
  meta:
    description = "datamaliciousorder - file 20160405_ad0f63da5e1632304edd38bdc1322879.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d03ad73359deca7b7fbb99d44f737f6f1dd47f12c761e71f803b321e6244a67c"

  strings:
    $s1  = "var xvg = IFTN(wEta + \"B.\" + baF[5]+(32704, baF[4]));" fullword ascii
    $s2  = "return jAkxbWL[0] + jAkxbWL[2] + jAkxbWL[4] + \".F\" + jAkxbWL[7] + jAkxbWL[9] + jAkxbWL[12] + jAkxbWL[14];" fullword ascii
    $s3  = "var Ha = true  , wEta = baF[7] + baF[9] + baF[11];" fullword ascii
    $s4  = "var baF = (\"2.XMLHTTP RGoFtyH lhjLs XML ream St MgRnroHz AD bOlcUCM O fBcL D\").split(\" \");" fullword ascii
    $s5  = "TIka.open(wIOdD,puIzG,false);" fullword ascii
    $s6  = "return lHXPooU(MU,QJYzn[505-499]+QJYzn[204-197]+QJYzn[761-753]);" fullword ascii
    $s7  = "function jMSl(iCpdJ,EOpru) {" fullword ascii
    $s8  = "if (qkbFN == 886-686){return true;} else {return false;}" fullword ascii
    $s9  = "function pMGZ(eMaHs) {" fullword ascii
    $s10 = "function BnhsvbM(Cgst) {" fullword ascii
    $s11 = "function CuKnHlqk(wxY) {" fullword ascii
    $s12 = "function laXs(vVonv) {" fullword ascii
    $s13 = "function CiGDq(eQLwzSpF,LUFT) {" fullword ascii
    $s14 = "function oKYY(zoPon) {" fullword ascii
    $s15 = "function YvCPDPCC(IPPz) {" fullword ascii
    $s16 = "return cyjmEaV[0];" fullword ascii
    $s17 = "return wxY.size;" fullword ascii
    $s18 = "if (vVonv > 159990-232){return true;} else {return false;}" fullword ascii
    $s19 = "function HlrZXR(VROYpZD) {" fullword ascii
    $s20 = "function JYpW(qkbFN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}