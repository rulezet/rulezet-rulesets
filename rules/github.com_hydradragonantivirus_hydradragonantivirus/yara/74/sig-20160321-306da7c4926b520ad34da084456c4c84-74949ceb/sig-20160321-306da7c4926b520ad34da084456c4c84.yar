rule sig_20160321_306da7c4926b520ad34da084456c4c84 {
  meta:
    description = "datamaliciousorder - file 20160321_306da7c4926b520ad34da084456c4c84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6be0f2f2d4f3e6f2836ebbfa3a6863a8c25c632d36d0ae338f054f74e58879d5"

  strings:
    $s1  = "var ZefkKHH = KvhSY(aIPIUsmgcr+\" \"+\"System Fh OMgkJ Obj nvhoDY ect HNfdlLR bvZCR\", \" \");" fullword ascii
    $s2  = "return WScript.CreateObject(cvINa);" fullword ascii
    $s3  = "var DJ = true  , SrFT = kVn[7] + kVn[9] + kVn[11];" fullword ascii
    $s4  = "return ZefkKHH[0] + ZefkKHH[2] + ZefkKHH[4] + \".F\" + ZefkKHH[7] + ZefkKHH[9] + ZefkKHH[12] + ZefkKHH[14];" fullword ascii
    $s5  = "var kVn = (\"2.XMLHTTP uelqIZJ GfiZm XML ream St rPSQFuNt AD crDWXVo O groH D\").split(\" \");" fullword ascii
    $s6  = "fsuFs.open(Rhznj,uwbav,false);" fullword ascii
    $s7  = "if(n>=l.length) {break;}" fullword ascii
    $s8  = "function NGgV(QgNFi,OPzZR) {" fullword ascii
    $s9  = "return CUq.size;" fullword ascii
    $s10 = "function KvhSY(niG,DVGNr) {" fullword ascii
    $s11 = "return new ActiveXObject(eJWQvW);" fullword ascii
    $s12 = "return niG.split(DVGNr);" fullword ascii
    $s13 = "function wdCB(tVbmg) {" fullword ascii
    $s14 = "function MLXX(fsuFs,uwbav,Rhznj) {" fullword ascii
    $s15 = "var SB = yooP(fg).split(\" \");" fullword ascii
    $s16 = "function hSha(MCEbE) {" fullword ascii
    $s17 = "function jQQvCMy(LsGF) {" fullword ascii
    $s18 = "return WMegr;" fullword ascii
    $s19 = "if (D >= SUBPP.length) {break;}" fullword ascii
    $s20 = "function CfjQC(pfmyqw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}