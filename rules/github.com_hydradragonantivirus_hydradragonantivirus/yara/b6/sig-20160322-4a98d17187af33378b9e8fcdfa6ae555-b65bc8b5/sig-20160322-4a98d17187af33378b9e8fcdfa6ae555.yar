rule sig_20160322_4a98d17187af33378b9e8fcdfa6ae555 {
  meta:
    description = "datamaliciousorder - file 20160322_4a98d17187af33378b9e8fcdfa6ae555.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b0477216b197cdb88db59fe06498f416a384e723e6b8c412ebd455c1e0f57b"

  strings:
    $s1  = "return WScript.CreateObject(bpZBw);" fullword ascii
    $s2  = "return IFmWczQ[0] + IFmWczQ[2] + IFmWczQ[4] + \".F\" + IFmWczQ[7] + IFmWczQ[9] + IFmWczQ[12] + IFmWczQ[14];" fullword ascii
    $s3  = "var Fz = true  , RMcm = rpk[7] + rpk[9] + rpk[11];" fullword ascii
    $s4  = "var IFmWczQ = ojyuG(WIGPqOtNku+\" \"+\"System iC EMshf Obj etIamQ ect rrjZzKd TEYaC\", \" \");" fullword ascii
    $s5  = "var rpk = (\"2.XMLHTTP MufEPzj NJJOm XML ream St PsxdGVWq AD hcKygEH O FskF D\").split(\" \");" fullword ascii
    $s6  = "zQlP.open(qcyyE,DaKAi,false);" fullword ascii
    $s7  = "return jFZV[vlVeGH[0]];" fullword ascii
    $s8  = "return LJpCwW.position=601-601;" fullword ascii
    $s9  = "return WDtz.ExpandEnvironmentStrings(UDmPP);" fullword ascii
    $s10 = "function NQBSE(FvqlzQ) {" fullword ascii
    $s11 = "Thr = D; break; " fullword ascii
    $s12 = "if (MPiXQ == 1143-943){return true;} else {return false;}" fullword ascii
    $s13 = "function gVmJ(aNIqk) {" fullword ascii
    $s14 = "function fOuubSM(WDtz,UDmPP) {" fullword ascii
    $s15 = "if (Q >= aNIqk.length) {break;}" fullword ascii
    $s16 = "function cZnshScg(wfqA) {" fullword ascii
    $s17 = "function XMoDuoP(jFZV) {" fullword ascii
    $s18 = "function YBZe(ZinMJ) {" fullword ascii
    $s19 = "return qMu.size;" fullword ascii
    $s20 = "if (UmaHC > 160502-310){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}