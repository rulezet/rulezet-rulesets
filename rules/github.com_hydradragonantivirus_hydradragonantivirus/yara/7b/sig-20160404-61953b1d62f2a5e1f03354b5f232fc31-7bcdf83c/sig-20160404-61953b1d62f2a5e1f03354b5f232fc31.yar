rule sig_20160404_61953b1d62f2a5e1f03354b5f232fc31 {
  meta:
    description = "datamaliciousorder - file 20160404_61953b1d62f2a5e1f03354b5f232fc31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69aa24900a7ed762d9658c243922c766e908f5932b7b98d74f53348c5999eba4"

  strings:
    $s1  = "var Co = true  , aflM = Typ[7] + Typ[9] + Typ[11];" fullword ascii
    $s2  = "return NmStBUe[0] + NmStBUe[2] + NmStBUe[4] + \".F\" + NmStBUe[7] + NmStBUe[9] + NmStBUe[12] + NmStBUe[14];" fullword ascii
    $s3  = "JCjr.open(VDUPY,pkqgD,false);" fullword ascii
    $s4  = "var Typ = (\"2.XMLHTTP gSPhnYJ uVLJt XML ream St YHrvjWMz AD qHSvymS O OUSJ D\").split(\" \");" fullword ascii
    $s5  = "var NmStBUe = zcgEE(LrSazHHacb+\" \"+\"System Pt uEvSz Obj NIGUNu ect DcfJGno tmAwd\", \" \");" fullword ascii
    $s6  = "return RhBqo;" fullword ascii
    $s7  = "function NgYK(ZnEXu) {" fullword ascii
    $s8  = "function Rzfh(UgjEB) {" fullword ascii
    $s9  = "function VkxPXc(gljugnp) {" fullword ascii
    $s10 = "function yAzRNg(YdmH,sYKLMB) {" fullword ascii
    $s11 = "function DZGZ(NuqNr) {" fullword ascii
    $s12 = "function EgJy(eUoEl) {" fullword ascii
    $s13 = "if (UgjEB > 159376-257){return true;} else {return false;}" fullword ascii
    $s14 = "if (uZZes == 379-179){return true;} else {return false;}" fullword ascii
    $s15 = "function PmNg(wpCRV,pkqgD,VDUPY) {" fullword ascii
    $s16 = "function DKYD(CWEzU) {" fullword ascii
    $s17 = "function Eimx(nQFaI,drQcm) {" fullword ascii
    $s18 = "return kwlD;" fullword ascii
    $s19 = "rth = V; break; " fullword ascii
    $s20 = "return bxJl[xlcpgX[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}