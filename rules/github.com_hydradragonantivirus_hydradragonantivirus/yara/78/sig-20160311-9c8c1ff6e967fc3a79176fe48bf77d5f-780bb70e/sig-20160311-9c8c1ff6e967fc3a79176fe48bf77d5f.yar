rule sig_20160311_9c8c1ff6e967fc3a79176fe48bf77d5f {
  meta:
    description = "datamaliciousorder - file 20160311_9c8c1ff6e967fc3a79176fe48bf77d5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92609871eb7f561cc675ac93f7551e37847bddac52ee5d3bfe6e1be2f979bf38"

  strings:
    $s1  = "function XiEHdLLh() {" fullword ascii
    $s2  = "var ff = true  , sAZk = Gtb[7] + Gtb[9] + Gtb[11];" fullword ascii
    $s3  = "return SIndEHN[0] + SIndEHN[2] + SIndEHN[4] + \".F\" + SIndEHN[7] + SIndEHN[9] + SIndEHN[12] + SIndEHN[14];" fullword ascii
    $s4  = "HhdXZ.open(vmfsP,lalbl,false);" fullword ascii
    $s5  = "var SIndEHN = \"Sc yJfHibU r zjXwYTPgt ipting JUpnMib oUO ile ScWWfxuvMevlmL System sH MmCtH Obj FUSdUA ect luFrKho\".split(\" " ascii
    $s6  = "var Gtb = (\"2.XMLHTTP iJduWmn yyTUv XML ream St QkiLCPfQ AD CRaGcmO O NETf D\").split(\" \");" fullword ascii
    $s7  = "function xTSi(HhdXZ,lalbl,vmfsP) {" fullword ascii
    $s8  = "if (Hhenu == 671-471){return true;} else {return false;}" fullword ascii
    $s9  = "function wpPB(Hhenu) {" fullword ascii
    $s10 = "function Jlor(jNSpx) {" fullword ascii
    $s11 = "function VHCz(zgmnE) {" fullword ascii
    $s12 = "if (UDydM > 127699-189){return true;} else {return false;}" fullword ascii
    $s13 = "function JPMRkEiZq(ksDiqIWnkiS) {" fullword ascii
    $s14 = "return vxNU.responseBody;" fullword ascii
    $s15 = "function AetYEvIc(nSZGx,snbaUa) {" fullword ascii
    $s16 = "YrL = E; break; " fullword ascii
    $s17 = "function XtJl(vjNao) {" fullword ascii
    $s18 = "function eSWg(ccEvQ,UxZLd) {" fullword ascii
    $s19 = "return XHKkLxQ(xi,Ehlbp[922-916]+Ehlbp[437-430]+Ehlbp[505-497]);" fullword ascii
    $s20 = "function qhLMx(yVnkrh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}