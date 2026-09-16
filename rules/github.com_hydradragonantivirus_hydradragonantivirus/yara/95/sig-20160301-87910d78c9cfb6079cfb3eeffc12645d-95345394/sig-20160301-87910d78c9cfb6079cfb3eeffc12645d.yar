rule sig_20160301_87910d78c9cfb6079cfb3eeffc12645d {
  meta:
    description = "datamaliciousorder - file 20160301_87910d78c9cfb6079cfb3eeffc12645d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e95d18e4ec137846d200a92f5a273ee167b3255d63f53df0c2ad504a4116f6c"

  strings:
    $s1  = "var kh = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(MRsZU);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + KusnXDv + \".F\" + hIRiJQyKHA + DbEbW + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var sh = true  , Rwrb = MBc[7] + \"\" + MBc[9];" fullword ascii
    $s5  = "var MBc = (kSt + \"TTP\" + \" gGklrCz FHiYo XML ream St kJzGXawG AD DlgnvAt OD\").split(\" \");" fullword ascii
    $s6  = "CxmFn.open(tFmgc,KKrau,false);" fullword ascii
    $s7  = "if (((new Date())>0,7540003888)) {" fullword ascii
    $s8  = "function IUyL(faWgD) {" fullword ascii
    $s9  = "tZz = h; break; " fullword ascii
    $s10 = "function MKoFw(cRylCd) {" fullword ascii
    $s11 = "return PZ.ExpandEnvironmentStrings(kh);" fullword ascii
    $s12 = "function rsYK(GuyKl,CEbMP) {" fullword ascii
    $s13 = "function IkrE(HmesG) {" fullword ascii
    $s14 = "function pMur(WFnRC) {" fullword ascii
    $s15 = "return new ActiveXObject(cRylCd);" fullword ascii
    $s16 = "function KmiD(WiGbv) {" fullword ascii
    $s17 = "if (fXbDg == 1089-889){return true;} else {return false;}" fullword ascii
    $s18 = "function dabD(nkWOK,zdeBV) {" fullword ascii
    $s19 = "function iemh(CxmFn,KKrau,tFmgc) {" fullword ascii
    $s20 = "function CfnY(XAqGF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}