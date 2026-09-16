rule sig_20160309_37b72595140defad06892ad287b2e063 {
  meta:
    description = "datamaliciousorder - file 20160309_37b72595140defad06892ad287b2e063.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fd42db23ae80f2656b62a529685a9f38c4939241736b736a69f9169f3b265f4"

  strings:
    $s1  = "var VX = true  , wVZd = yiL[7] + yiL[9] + yiL[11];" fullword ascii
    $s2  = "return INvnTvM[0] + INvnTvM[2] + INvnTvM[4] + \".F\" + INvnTvM[7] + INvnTvM[9] + INvnTvM[12] + INvnTvM[14];" fullword ascii
    $s3  = "var yiL = (\"2.XMLHTTP KhihrpA LxStM XML ream St bnLZNFBc AD XiDvogk O QOdg D\").split(\" \");" fullword ascii
    $s4  = "eEfcK.open(wopAy,RozoW,false);" fullword ascii
    $s5  = "var INvnTvM = \"Sc sGEMmVJ r PNSfBYsuu ipting qdJQkGt vll ile vjUkHFzgLjCVKy System PG kghkU Obj evTzon ect VRUvQoW\".split(\" " ascii
    $s6  = "function ASQW(bGaDL) {" fullword ascii
    $s7  = "return GZnf.ExpandEnvironmentStrings(Qczqn);" fullword ascii
    $s8  = "function hNsIQ(xxMDNC) {" fullword ascii
    $s9  = "return ZSvxg;" fullword ascii
    $s10 = "function KYed(pmuDV) {" fullword ascii
    $s11 = "function UbWe(wtKIu) {" fullword ascii
    $s12 = "function ZGiK(RjdAY,BuKQA) {" fullword ascii
    $s13 = "function VxSqmYxaQ(ltxcbqDSGuc) {" fullword ascii
    $s14 = "function THua(oLwfh) {" fullword ascii
    $s15 = "function JxYodicz(Ndv) {" fullword ascii
    $s16 = "function Fakm(CbVQk) {" fullword ascii
    $s17 = "if (uTvlO > 168520-548){return true;} else {return false;}" fullword ascii
    $s18 = "return BOlmbtd(JU,okFAU[664-658]+okFAU[321-314]+okFAU[533-525]);" fullword ascii
    $s19 = "function lyybEhz(QlFV) {" fullword ascii
    $s20 = "if(x>=q.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}