rule sig_20160309_fd2ff251c859482d8edebb3c72fd456a {
  meta:
    description = "datamaliciousorder - file 20160309_fd2ff251c859482d8edebb3c72fd456a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a729ba56e28e6cc287cd007be17090b7820d79dd8b6c6a5abc462cd94e6e9b61"

  strings:
    $s1  = "return ivXncxq[0] + ivXncxq[2] + ivXncxq[4] + \".F\" + ivXncxq[7] + ivXncxq[9] + ivXncxq[12] + ivXncxq[14];" fullword ascii
    $s2  = "var nr = true  , NgcY = qNS[7] + qNS[9] + qNS[11];" fullword ascii
    $s3  = "XjJst.open(bTdnH,Wzrpv,false);" fullword ascii
    $s4  = "var ivXncxq = \"Sc aqvjGxJ r fmVrZcMVN ipting yTsFXBb cUO ile gWctfPjXITFtiX System tJ Ivwkh Obj QYgchW ect LXedJtH\".split(\" " ascii
    $s5  = "var qNS = (\"2.XMLHTTP gWvcnxw zQhlp XML ream St ltEcpuQj AD scQmCbq O OlJV D\").split(\" \");" fullword ascii
    $s6  = "return ENm.size;" fullword ascii
    $s7  = "function GYpQLrUoR(OgTbDEvGcKz) {" fullword ascii
    $s8  = "function fcpyBcBV(ENm) {" fullword ascii
    $s9  = "function OqcGLpE(jGjM) {" fullword ascii
    $s10 = "function DGWKowqX(wFKDW,dTVVLR) {" fullword ascii
    $s11 = "function ojzw(OqbHX) {" fullword ascii
    $s12 = "cSk = z; break; " fullword ascii
    $s13 = "function lYHV(vRBUY) {" fullword ascii
    $s14 = "return nGiAu.status;" fullword ascii
    $s15 = "function BMfV(NUpyU) {" fullword ascii
    $s16 = "return apbuYoD(fe,umiae[487-481]+umiae[172-165]+umiae[474-466]);" fullword ascii
    $s17 = "function HvCD(JUWwA) {" fullword ascii
    $s18 = "function MlBT(aJsmD) {" fullword ascii
    $s19 = "return jGjM.responseBody;" fullword ascii
    $s20 = "if (NUpyU == 1070-870){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}