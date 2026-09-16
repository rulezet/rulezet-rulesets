rule sig_20160321_6faab526603ed481578ae38d9d2738bd {
  meta:
    description = "datamaliciousorder - file 20160321_6faab526603ed481578ae38d9d2738bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d99eb594078f28c83655e717d983200189b6bcf6b9d56627b242c750976016d"

  strings:
    $s1  = "return WScript.CreateObject(VWZjE);" fullword ascii
    $s2  = "var NP = true  , aEdO = Nio[7] + Nio[9] + Nio[11];" fullword ascii
    $s3  = "return XjcCkYa[0] + XjcCkYa[2] + XjcCkYa[4] + \".F\" + XjcCkYa[7] + XjcCkYa[9] + XjcCkYa[12] + XjcCkYa[14];" fullword ascii
    $s4  = "var Nio = (\"2.XMLHTTP dbZeOwS ssRDx XML ream St krvvbgwV AD dUQViJZ O RzdU D\").split(\" \");" fullword ascii
    $s5  = "xMDyG.open(hsBGW,WZEeI,false);" fullword ascii
    $s6  = "var XjcCkYa = mVDPG(IIDmllexvV+\" \"+\"System un fGoit Obj EAwMDu ect UosvZBi MuqHH\", \" \");" fullword ascii
    $s7  = "if(y>=M.length) {break;}" fullword ascii
    $s8  = "function XljGgCZEt(MvwFYnOJdQC) {" fullword ascii
    $s9  = "function JPAz(fyweX) {" fullword ascii
    $s10 = "function mVDPG(LAP,PiSsC) {" fullword ascii
    $s11 = "return amMNjNf(Uh,DcYaC[904-898]+DcYaC[736-729]+DcYaC[898-890]);" fullword ascii
    $s12 = "CgF = y; break; " fullword ascii
    $s13 = "function rcEajsdK(MJx) {" fullword ascii
    $s14 = "function pplu(xMDyG,WZEeI,hsBGW) {" fullword ascii
    $s15 = "return MJx.size;" fullword ascii
    $s16 = "return new ActiveXObject(UXZLSZ);" fullword ascii
    $s17 = "function hEhtYMc(QsOi) {" fullword ascii
    $s18 = "return Eisx.ExpandEnvironmentStrings(fJZOD);" fullword ascii
    $s19 = "function rdEUO(UXZLSZ) {" fullword ascii
    $s20 = "function sXcD(ZPpgP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}