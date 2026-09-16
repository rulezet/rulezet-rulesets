rule sig_20160314_411da4fd4a53e01efe8eda8a5e1423b4 {
  meta:
    description = "datamaliciousorder - file 20160314_411da4fd4a53e01efe8eda8a5e1423b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e328a59fa8b5fd7e6417184501a7061cd72480f1901868349473ef51abc1d9fc"

  strings:
    $s1  = "function FEqzpdm(HOst) {" fullword ascii
    $s2  = "return HOst.responseBody;" fullword ascii
    $s3  = "var fP = true  , cFZC = MoH[7] + MoH[9] + MoH[11];" fullword ascii
    $s4  = "return PiJaVGt[0] + PiJaVGt[2] + PiJaVGt[4] + \".F\" + PiJaVGt[7] + PiJaVGt[9] + PiJaVGt[12] + PiJaVGt[14];" fullword ascii
    $s5  = "var PiJaVGt = \"Sc IBOfhEo r HwuereFrM ipting RYAafte yiQ ile gzHGxLaGvfFKlS System Yp JJfyg Obj FqPNGm ect ZZtSzQA ZJjna\".spli" ascii
    $s6  = "Wqn.CreateFolder(pIpI);" fullword ascii
    $s7  = "var MoH = (\"2.XMLHTTP DvDXdNn EiTpn XML ream St tyryCrne AD TgimjPZ O TNhq D\").split(\" \");" fullword ascii
    $s8  = "var PiJaVGt = \"Sc IBOfhEo r HwuereFrM ipting RYAafte yiQ ile gzHGxLaGvfFKlS System Yp JJfyg Obj FqPNGm ect ZZtSzQA ZJjna\".spli" ascii
    $s9  = "Xxrzk.open(bNuWP,rraPi,false);" fullword ascii
    $s10 = "function Jtmw(xikGh) {" fullword ascii
    $s11 = "return odAVC.status;" fullword ascii
    $s12 = "function tAmvfkzd(Uxq) {" fullword ascii
    $s13 = "if (ciZpu > 156857-596){return true;} else {return false;}" fullword ascii
    $s14 = "function iHuWmlKim() {" fullword ascii
    $s15 = "function VTrR(xcLJq) {" fullword ascii
    $s16 = "return new ActiveXObject(rESSqC);" fullword ascii
    $s17 = "function Fvlz(Xxrzk,rraPi,bNuWP) {" fullword ascii
    $s18 = "QHj = S; break; " fullword ascii
    $s19 = "function GOul(odAVC) {" fullword ascii
    $s20 = "function AakJ(ciZpu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}