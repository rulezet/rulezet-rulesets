rule sig_20160411_f721824e4ad867d0c423d8d45768233d {
  meta:
    description = "datamaliciousorder - file 20160411_f721824e4ad867d0c423d8d45768233d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee303759287c9b6096fe6cc0fc94e53db772a422c732d1b3cd5f051bfa7bc1bc"

  strings:
    $s1  = "var On = true  , wbsk = klO[7] + klO[9] + klO[11];" fullword ascii
    $s2  = "return pNpOPvU[0] + pNpOPvU[2] + pNpOPvU[4] + \".F\" + pNpOPvU[7] + pNpOPvU[9] + pNpOPvU[12] + pNpOPvU[14];" fullword ascii
    $s3  = "var klO = (\"2.XMLHTTP SFbkFmu iEIpz XML ream St THECoPZI AD DJLFbBs O QdpO D\").split(\" \");" fullword ascii
    $s4  = "YwIs.open(aMSpb,Sicqa,false);" fullword ascii
    $s5  = "if(S>=b.length) {break;}" fullword ascii
    $s6  = "function SCvmuSDYZ(jxbOFWaXXSI) {" fullword ascii
    $s7  = "return \"zwSpGWWgKZgtdX\";" fullword ascii
    $s8  = "return qlCx[tzUmKcJ[0]+tzUmKcJ[1]];" fullword ascii
    $s9  = "function PJPmzHSL(Rzxu) {" fullword ascii
    $s10 = "function PwkGwCR(VNNl,SlEVR) {" fullword ascii
    $s11 = "function teFETkQi(dzy) {" fullword ascii
    $s12 = "function dHSEYx(IaXKyww) {" fullword ascii
    $s13 = "if (urfoi > 175260-965){return true;} else {return false;}" fullword ascii
    $s14 = "function ULIh(ppRcX) {" fullword ascii
    $s15 = "if (MWOeJ == 883-683){return true;} else {return false;}" fullword ascii
    $s16 = "function JEQYQF(JdZZ,WNiDyd) {" fullword ascii
    $s17 = "return new ActiveXObject(nDuL);" fullword ascii
    $s18 = "return SoiSS.status;" fullword ascii
    $s19 = "return iVRfnjb[0];" fullword ascii
    $s20 = "function NaHNvJW(qlCx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}