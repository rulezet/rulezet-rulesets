rule sig_20160323_f6e634c867afd5eb1285bdb2299d04e5 {
  meta:
    description = "datamaliciousorder - file 20160323_f6e634c867afd5eb1285bdb2299d04e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "223070fa74162ce2eb71b7d45995b55c85d120faa26a14e0a32fd1ebd49706c7"

  strings:
    $s1  = "return WScript.CreateObject(hArsL);" fullword ascii
    $s2  = "var ti = true  , Kyve = CgO[7] + CgO[9] + CgO[11];" fullword ascii
    $s3  = "return gGzXmrR[0] + gGzXmrR[2] + gGzXmrR[4] + \".F\" + gGzXmrR[7] + gGzXmrR[9] + gGzXmrR[12] + gGzXmrR[14];" fullword ascii
    $s4  = "var CgO = (\"2.XMLHTTP LISFQZN EaHKo XML ream St PvNpiodI AD jRyziZC O ygIN D\").split(\" \");" fullword ascii
    $s5  = "eNJQ.open(CDgfg,uPahU,false);" fullword ascii
    $s6  = "var gGzXmrR = sQdxu(mMysOzWYXw+\" \"+\"System nl RTsUQ Obj iMaqlZ ect eClrtye xktcJ\", \" \");" fullword ascii
    $s7  = "if(i>=l.length) {break;}" fullword ascii
    $s8  = "jqzIx[bARu[526-526]](EPhpII);" fullword ascii
    $s9  = "return xgDCv;" fullword ascii
    $s10 = "fLO = i; break; " fullword ascii
    $s11 = "return IMHybUh(Ox,iNKpP[495-489]+iNKpP[355-348]+iNKpP[362-354]);" fullword ascii
    $s12 = "function xwLT(yLKQs) {" fullword ascii
    $s13 = "function XRkS(BDUfB) {" fullword ascii
    $s14 = "function IMHybUh(OsKi,HlpwT) {" fullword ascii
    $s15 = "function KAdm(nKZmc) {" fullword ascii
    $s16 = "if (G >= UqXDb.length) {break;}" fullword ascii
    $s17 = "function uVTAfAp(HYZm) {" fullword ascii
    $s18 = "return new ActiveXObject(PCuU);" fullword ascii
    $s19 = "function ijXqmcwul(hMFrI) {" fullword ascii
    $s20 = "return HYZm[aXpEBt[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}