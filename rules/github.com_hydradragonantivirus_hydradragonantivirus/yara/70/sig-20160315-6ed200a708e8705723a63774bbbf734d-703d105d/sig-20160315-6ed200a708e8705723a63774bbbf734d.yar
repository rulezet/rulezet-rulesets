rule sig_20160315_6ed200a708e8705723a63774bbbf734d {
  meta:
    description = "datamaliciousorder - file 20160315_6ed200a708e8705723a63774bbbf734d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26bbc913eb808f702c0dddc4be95f0eaabe3573e970962bd1e8cadcff2e6a0ae"

  strings:
    $s1  = "var Mr = true  , EdEV = wVo[7] + wVo[9] + wVo[11];" fullword ascii
    $s2  = "return witglIl[0] + witglIl[2] + witglIl[4] + \".F\" + witglIl[7] + witglIl[9] + witglIl[12] + witglIl[14];" fullword ascii
    $s3  = "var witglIl = YjNIO(\"Sc RYugeOn r NXnmtXbIU ipting gcQvOeI JhB ile FClnRpUVKtLuxQ System gO HwCpV Obj nzjlAL ect ufhIozH oqcRB" ascii
    $s4  = "var wVo = (\"2.XMLHTTP HKCXgvU DfDzY XML ream St NZbPrdMS AD utvGLPv O MFfN D\").split(\" \");" fullword ascii
    $s5  = "MYvMj.open(qbBQS,iTrll,false);" fullword ascii
    $s6  = "var witglIl = YjNIO(\"Sc RYugeOn r NXnmtXbIU ipting gcQvOeI JhB ile FClnRpUVKtLuxQ System gO HwCpV Obj nzjlAL ect ufhIozH oqcRB" ascii
    $s7  = "return eIU.split(qTCGq);" fullword ascii
    $s8  = "if (nApVe == 799-599){return true;} else {return false;}" fullword ascii
    $s9  = "function scrVI(sQdpBM) {" fullword ascii
    $s10 = "function OXKu(BXHcD) {" fullword ascii
    $s11 = "if (YRLzI > 179718-260){return true;} else {return false;}" fullword ascii
    $s12 = "function EXyE(nApVe) {" fullword ascii
    $s13 = "function iHpilqVRp(sUAky) {" fullword ascii
    $s14 = "return uzDc.ExpandEnvironmentStrings(yXBHB);" fullword ascii
    $s15 = "if (z >= tjqyl.length) {break;}" fullword ascii
    $s16 = "if(R>=i.length) {break;}" fullword ascii
    $s17 = "function YjNIO(eIU,qTCGq) {" fullword ascii
    $s18 = "function WBno(fYEDB) {" fullword ascii
    $s19 = "function uljhA(QBzjtk) {" fullword ascii
    $s20 = "return bIuDX;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}