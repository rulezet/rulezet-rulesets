rule sig_20160314_80c97d3d3af81012362214545b7a3a2c {
  meta:
    description = "datamaliciousorder - file 20160314_80c97d3d3af81012362214545b7a3a2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f54e3cc54543171372358e5c3afd9c7eb3374ffe0ed7586e503385de202be24"

  strings:
    $s1  = "var GGDbYbb = \"Sc siPNnTB r suwicSDJa ipting oFhHztB Uml ile vFVcAVMNYBDZGe System NJ eVjkX Obj KRDLLg ect EbtAvGm iqKsF\".spli" ascii
    $s2  = "return GGDbYbb[0] + GGDbYbb[2] + GGDbYbb[4] + \".F\" + GGDbYbb[7] + GGDbYbb[9] + GGDbYbb[12] + GGDbYbb[14];" fullword ascii
    $s3  = "var GGDbYbb = \"Sc siPNnTB r suwicSDJa ipting oFhHztB Uml ile vFVcAVMNYBDZGe System NJ eVjkX Obj KRDLLg ect EbtAvGm iqKsF\".spli" ascii
    $s4  = "var kN = true  , DFSS = zAw[7] + zAw[9] + zAw[11];" fullword ascii
    $s5  = "LacZs.open(WNWyl,hqdOA,false);" fullword ascii
    $s6  = "var zAw = (\"2.XMLHTTP sMbgnfd taQWB XML ream St AQXhXCQi AD YiSokyw O Iumv D\").split(\" \");" fullword ascii
    $s7  = "return ShddO;" fullword ascii
    $s8  = "function GzNI(uPPGV) {" fullword ascii
    $s9  = "function QisjbtxJ() {" fullword ascii
    $s10 = "function QzZk(fardB) {" fullword ascii
    $s11 = "function adWRoZzs(xyJ) {" fullword ascii
    $s12 = "function AbYY(ZMEBJ) {" fullword ascii
    $s13 = "return KJrtwBC(Jv,LLByC[642-636]+LLByC[249-242]+LLByC[166-158]);" fullword ascii
    $s14 = "function lXlj(NPHYE) {" fullword ascii
    $s15 = "function KJrtwBC(KFBs,cWsDJ) {" fullword ascii
    $s16 = "if (uPPGV == 738-538){return true;} else {return false;}" fullword ascii
    $s17 = "function Xqog(YdjxB) {" fullword ascii
    $s18 = "function shkN(kWPSz,xPkHR) {" fullword ascii
    $s19 = "return CKtjoci" fullword ascii
    $s20 = "function Vagv(zqxdi,FdYaI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}