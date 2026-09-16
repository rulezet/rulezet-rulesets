rule sig_20160307_5e9bf415a95dcec4a34b7e3f76e9d564 {
  meta:
    description = "datamaliciousorder - file 20160307_5e9bf415a95dcec4a34b7e3f76e9d564.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7e93e47a73a84b02d3c092cee8d24c6e99b6ed248a308dfea9b2b3d15dadcdb"

  strings:
    $s1  = "var Pk = true  , YDcv = Zxs[7] + Zxs[9] + Zxs[11];" fullword ascii
    $s2  = "return rPSYrGx[0] + rPSYrGx[2] + rPSYrGx[4] + \".F\" + rPSYrGx[7] + rPSYrGx[9] + rPSYrGx[12] + rPSYrGx[14];" fullword ascii
    $s3  = "cnYHP.open(NMlQz,sIbUq,false);" fullword ascii
    $s4  = "var rPSYrGx = \"Sc RqcXLmT r OPtSVqIRw ipting HzEBbcb CEo ile wfcOIEkDzyyEBu System rp hJujX Obj lubLno ect FbmEXda\".split(\" " ascii
    $s5  = "var Zxs = (\"2.XMLHTTP bwvieFu TZpSV XML ream St PJygRRzR AD AJcwWXA O ZNeA D\").split(\" \");" fullword ascii
    $s6  = "function XwWfzDiYf(uJklI,FgDJp,tvzsm,pWpG) {" fullword ascii
    $s7  = "function QPolN(SBzGSV) {" fullword ascii
    $s8  = "function GbzV(pMzNp) {" fullword ascii
    $s9  = "if (PXVcr > 179333-851){return true;} else {return false;}" fullword ascii
    $s10 = "return tmZwn.status;" fullword ascii
    $s11 = "function KzBS(tmZwn) {" fullword ascii
    $s12 = "function yTiR(BdfRj) {" fullword ascii
    $s13 = "return ZJ.ExpandEnvironmentStrings(HaetH[6]+HaetH[7]+HaetH[8]);" fullword ascii
    $s14 = "function oTaLGZPd(CJD) {" fullword ascii
    $s15 = "if (((new Date())>0,7258343888)) {" fullword ascii
    $s16 = "function apVIfPd(uHNW) {" fullword ascii
    $s17 = "if (BdfRj == 884-684){return true;} else {return false;}" fullword ascii
    $s18 = "return fDLENhg" fullword ascii
    $s19 = "function OHAftOZJL(BThRQKWauRf) {" fullword ascii
    $s20 = "function vPvP(BmjbL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}