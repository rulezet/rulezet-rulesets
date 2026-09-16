rule sig_20160313_34f9e22b4cc49504dc834417dd41300b {
  meta:
    description = "datamaliciousorder - file 20160313_34f9e22b4cc49504dc834417dd41300b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38e77ed2d0c187b1bad0e9c9577e4244f70101a36808c2d0eee04339fdaf1aad"

  strings:
    $s1  = "var Fy = true  , SSzn = sVq[7] + sVq[9] + sVq[11];" fullword ascii
    $s2  = "return EAidvtH[0] + EAidvtH[2] + EAidvtH[4] + \".F\" + EAidvtH[7] + EAidvtH[9] + EAidvtH[12] + EAidvtH[14];" fullword ascii
    $s3  = "var sVq = (\"2.XMLHTTP XbwovZH hclWQ XML ream St RvmgEyXZ AD oYuEXvN O lWOH D\").split(\" \");" fullword ascii
    $s4  = "OHFqe.open(ZzpsZ,iJGDf,false);" fullword ascii
    $s5  = "var EAidvtH = \"Sc mQruGoU r eTKYsXrMo ipting EXBDfvH fLa ile XEjDjzwKaelTdF System nm Dictj Obj NAluNc ect llsgRGo\".split(\" " ascii
    $s6  = "if (aIDkH == 769-569){return true;} else {return false;}" fullword ascii
    $s7  = "function lyGW(SMoeT) {" fullword ascii
    $s8  = "function SnLgNmlQ(FpT) {" fullword ascii
    $s9  = "function XkrPQnd(GoeO,wmhbA) {" fullword ascii
    $s10 = "function iaxl(OHFqe,iJGDf,ZzpsZ) {" fullword ascii
    $s11 = "function Doqv(aIDkH) {" fullword ascii
    $s12 = "wRt = R; break; " fullword ascii
    $s13 = "return KqdLC.status;" fullword ascii
    $s14 = "function ziVb(gyTIi,bJgIT) {" fullword ascii
    $s15 = "function otGs(KqdLC) {" fullword ascii
    $s16 = "function Buvp(NvLCC) {" fullword ascii
    $s17 = "return HUPeUs.position=570-570;" fullword ascii
    $s18 = "function rCkpQ(HUPeUs) {" fullword ascii
    $s19 = "function OykZr(UIySGZ) {" fullword ascii
    $s20 = "function ExZLurGeh(LgYDPntfxfw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}