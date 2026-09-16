rule sig_20160324_7bca27314882d63853da8988c9802bbf {
  meta:
    description = "datamaliciousorder - file 20160324_7bca27314882d63853da8988c9802bbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd40ac580f02baa636d36ba1805eb01863b5fe266bf7cdf19e0d38bd5c2818f"

  strings:
    $s1  = "return WScript.CreateObject(HByCr);" fullword ascii
    $s2  = "var wa = true  , dJyQ = qqd[7] + qqd[9] + qqd[11];" fullword ascii
    $s3  = "return UxehYrP[0] + UxehYrP[2] + UxehYrP[4] + \".F\" + UxehYrP[7] + UxehYrP[9] + UxehYrP[12] + UxehYrP[14];" fullword ascii
    $s4  = "var qqd = (\"2.XMLHTTP MQuUfqI NxWBZ XML ream St rjsmtXJD AD EeIgwbj O geyZ D\").split(\" \");" fullword ascii
    $s5  = "var UxehYrP = YgGFw(XOksZbRXwA+\" \"+\"System dt JnnSo Obj HuKpmV ect LgFiadd jPuWh\", \" \");" fullword ascii
    $s6  = "nXYm.open(mtBAi,STGSC,false);" fullword ascii
    $s7  = "if (MLTPr == 607-407){return true;} else {return false;}" fullword ascii
    $s8  = "if (vlXax > 174985-590){return true;} else {return false;}" fullword ascii
    $s9  = "function kpNL(MLTPr) {" fullword ascii
    $s10 = "function NcuJF(HltIhQ) {" fullword ascii
    $s11 = "function zUuAB(rGTDuiMh,MtTs) {" fullword ascii
    $s12 = "function daQS(dRFAm) {" fullword ascii
    $s13 = "return PGAp.ExpandEnvironmentStrings(AbIxN);" fullword ascii
    $s14 = "return FJvmE;" fullword ascii
    $s15 = "return qea.size;" fullword ascii
    $s16 = "aGK = M; break; " fullword ascii
    $s17 = "return ttmvi.status;" fullword ascii
    $s18 = "function VGuX(JcqNq) {" fullword ascii
    $s19 = "function kubVgshKb(CmBPhJZIpRg) {" fullword ascii
    $s20 = "var jRGnxaa = \"rKrLLG*vyb*pt.S\"+\"hell*DvBGktt*Scri*\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}