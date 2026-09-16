rule sig_20160311_ac7cf5fe98311410ca4bad1031769f52 {
  meta:
    description = "datamaliciousorder - file 20160311_ac7cf5fe98311410ca4bad1031769f52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d71e8ada9418c3fd2b7a112154f6bcee8ddc21f39e6e57e7c7dc384ec062a5a8"

  strings:
    $s1  = "var aG = true  , bYkn = LmT[7] + LmT[9] + LmT[11];" fullword ascii
    $s2  = "return qkvfHVY[0] + qkvfHVY[2] + qkvfHVY[4] + \".F\" + qkvfHVY[7] + qkvfHVY[9] + qkvfHVY[12] + qkvfHVY[14];" fullword ascii
    $s3  = "var qkvfHVY = \"Sc FfZIRJM r GGAmBGAxM ipting DMDsAmS Wub ile rtSBrLKmRLAmVm System qj VrRCO Obj QEIope ect mrKoawX\".split(\" " ascii
    $s4  = "ZQHlm.open(PZRkB,wMIyC,false);" fullword ascii
    $s5  = "var LmT = (\"2.XMLHTTP esgipJY DqpOc XML ream St ALBtMrQk AD zavlQAX O CbsL D\").split(\" \");" fullword ascii
    $s6  = "return cSnuaEA(xN,JatGu[864-858]+JatGu[665-658]+JatGu[674-666]);" fullword ascii
    $s7  = "function GPCz(AYwNR) {" fullword ascii
    $s8  = "function jivbPRAdH(KYWQiGDPtdD) {" fullword ascii
    $s9  = "function GbKrMvbh(YnACt,SDkOHs) {" fullword ascii
    $s10 = "function RVUb(Irmlm,tZdwP) {" fullword ascii
    $s11 = "if (khHud == 452-252){return true;} else {return false;}" fullword ascii
    $s12 = "function ASKLGGdqT() {" fullword ascii
    $s13 = "function cSnuaEA(jtut,aGdfV) {" fullword ascii
    $s14 = "function KPlZQTMs() {" fullword ascii
    $s15 = "function Chka(OdDfv,ZAuoJ) {" fullword ascii
    $s16 = "return pzfGs;" fullword ascii
    $s17 = "function WXUJ(ZZbCp) {" fullword ascii
    $s18 = "function chnZ(khHud) {" fullword ascii
    $s19 = "function OUaL(aRBzD) {" fullword ascii
    $s20 = "return SwIPLm.position=297-297;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}