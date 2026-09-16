rule sig_20160308_c334612afb1b2c1221957cc69e13705b {
  meta:
    description = "datamaliciousorder - file 20160308_c334612afb1b2c1221957cc69e13705b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dc23c81335225b2b01c531c2af70595363bacdf043edc3ca681162b7d12d1c8"

  strings:
    $s1  = "var Yt = true  , jpfr = fAV[7] + fAV[9] + fAV[11];" fullword ascii
    $s2  = "return yqcsRbl[0] + yqcsRbl[2] + yqcsRbl[4] + \".F\" + yqcsRbl[7] + yqcsRbl[9] + yqcsRbl[12] + yqcsRbl[14];" fullword ascii
    $s3  = "gBUoC.open(cSlTJ,laacT,false);" fullword ascii
    $s4  = "var fAV = (\"2.XMLHTTP MiAdfdG HQpCv XML ream St wxSuIpwz AD dfYeawk O GuNQ D\").split(\" \");" fullword ascii
    $s5  = "var yqcsRbl = \"Sc iDEphBr r bVmDlaPmx ipting IDGvSGc bzQ ile LPoKjVHJaSbxGI System cm wUXcE Obj nJirae ect llbtcqM\".split(\" " ascii
    $s6  = "function SpIs(znCZb) {" fullword ascii
    $s7  = "function UvtBSqAf() {" fullword ascii
    $s8  = "Hlf = B; break; " fullword ascii
    $s9  = "return nbW.size;" fullword ascii
    $s10 = "if(B>=X.length) {break;}" fullword ascii
    $s11 = "return EwqJ.responseBody;" fullword ascii
    $s12 = "function LpMo(gBUoC,laacT,cSlTJ) {" fullword ascii
    $s13 = "function vFsMtRPTb(aJHHOefIDwM) {" fullword ascii
    $s14 = "function OEhx(isUXc,CpTFB) {" fullword ascii
    $s15 = "return bJbgU.status;" fullword ascii
    $s16 = "function KotvwRm(EwqJ) {" fullword ascii
    $s17 = "function crjXJVHRR(lkQNG,Ajmer,mdJBz,cRjr) {" fullword ascii
    $s18 = "if (N >= SpScI.length) {break;}" fullword ascii
    $s19 = "return zvHQI;" fullword ascii
    $s20 = "function duoB(YKdIY,CQiFz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}