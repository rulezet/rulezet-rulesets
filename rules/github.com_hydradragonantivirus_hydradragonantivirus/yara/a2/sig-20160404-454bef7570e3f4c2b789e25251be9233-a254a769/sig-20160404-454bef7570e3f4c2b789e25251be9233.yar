rule sig_20160404_454bef7570e3f4c2b789e25251be9233 {
  meta:
    description = "datamaliciousorder - file 20160404_454bef7570e3f4c2b789e25251be9233.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1e53475e6711e37a348d5b7f13d697fe18a462f1e77f9c98de4430dc610b832"

  strings:
    $s1  = "var zv = true  , TjEF = MoV[7] + MoV[9] + MoV[11];" fullword ascii
    $s2  = "return YXIdghk[0] + YXIdghk[2] + YXIdghk[4] + \".F\" + YXIdghk[7] + YXIdghk[9] + YXIdghk[12] + YXIdghk[14];" fullword ascii
    $s3  = "aXgF.open(wMEqr,qGAZf,false);" fullword ascii
    $s4  = "var YXIdghk = fhSxb(kBGjzLOare+\" \"+\"System cv WhgqQ Obj cWFYPP ect sLJADlX OGHUQ\", \" \");" fullword ascii
    $s5  = "var MoV = (\"2.XMLHTTP dsvhzFW rzaIS XML ream St ZGrAibFF AD VkOlDuZ O tfOP D\").split(\" \");" fullword ascii
    $s6  = "return \"DhVTApHNzHdRKq\";" fullword ascii
    $s7  = "function FCRq(cbnFe) {" fullword ascii
    $s8  = "function txlT(MvNnv,PENTd) {" fullword ascii
    $s9  = "function YfveL(sZsmzn) {" fullword ascii
    $s10 = "function TJjm(SPlNG) {" fullword ascii
    $s11 = "function fhSxb(cPC,ATSBu) {" fullword ascii
    $s12 = "if (IePWR > 175638-553){return true;} else {return false;}" fullword ascii
    $s13 = "return ymNbv;" fullword ascii
    $s14 = "return FCQzQLv;" fullword ascii
    $s15 = "function qQOd(jCVpA) {" fullword ascii
    $s16 = "function GtHGJcr(VzkX,MMODf) {" fullword ascii
    $s17 = "return cPC.split(ATSBu);" fullword ascii
    $s18 = "function UErRaBglS(awRrejYEPBe) {" fullword ascii
    $s19 = "return BxK.size;" fullword ascii
    $s20 = "function gfdGAWwas(TWtqo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}