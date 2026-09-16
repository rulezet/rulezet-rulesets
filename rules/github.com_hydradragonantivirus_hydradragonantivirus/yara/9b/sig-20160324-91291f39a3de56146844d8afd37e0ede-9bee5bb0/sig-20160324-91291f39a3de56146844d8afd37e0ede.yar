rule sig_20160324_91291f39a3de56146844d8afd37e0ede {
  meta:
    description = "datamaliciousorder - file 20160324_91291f39a3de56146844d8afd37e0ede.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28b9997a6f3ebdbbe44a9aa65bf985b6877c3a15f9b1141d077e04ee616776c0"

  strings:
    $s1  = "return WScript.CreateObject(UkaBk);" fullword ascii
    $s2  = "return jLBdIxl[0] + jLBdIxl[2] + jLBdIxl[4] + \".F\" + jLBdIxl[7] + jLBdIxl[9] + jLBdIxl[12] + jLBdIxl[14];" fullword ascii
    $s3  = "var jLBdIxl = YXrWX(BiWiHLhGuF+\" \"+\"System cp djkHJ Obj ERKomc ect RAGLcbo qfoWL\", \" \");" fullword ascii
    $s4  = "hpEj.open(SvfCC,ZWmmp,false);" fullword ascii
    $s5  = "function osUqpajfF(rRtMlSIVXie) {" fullword ascii
    $s6  = "return VHcBXJ/*tXAcq9NVXBflq14xFyDQr1HFo*/.position=573-573;" fullword ascii
    $s7  = "if (utrMd > 160742-740){return true;} else {return false;}" fullword ascii
    $s8  = "function vRolFfmCr(VKrmO) {" fullword ascii
    $s9  = "function rRJzsmq(JTOg,DAtJT) {" fullword ascii
    $s10 = "function QZkIF(nmXZBB) {" fullword ascii
    $s11 = "return NGHDP.status;" fullword ascii
    $s12 = "return Opf.split(kcxGY);" fullword ascii
    $s13 = "function Sgld(XeKUz) {" fullword ascii
    $s14 = "function KBlrE(VHcBXJ) {" fullword ascii
    $s15 = "function kIVZ(NGHDP) {" fullword ascii
    $s16 = "var WTXHaly = \"wYIyGi*ApU*pt.S\"+\"hell*haWQfpF*Scri*\";" fullword ascii
    $s17 = "return zwh.size;" fullword ascii
    $s18 = "function YXrWX(Opf,kcxGY) {" fullword ascii
    $s19 = "return new ActiveXObject(tgbm);" fullword ascii
    $s20 = "function vPyKIxGb(Mmdy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}