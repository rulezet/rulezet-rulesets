rule sig_20160308_075e57edb7a2b7f998491968eade6076 {
  meta:
    description = "datamaliciousorder - file 20160308_075e57edb7a2b7f998491968eade6076.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29a623fe465e1f98c5d51cea7a7619b80d04562ffe0b121c47170bb2a0b22feb"

  strings:
    $s1  = "function KhcJmjeYE(cHZbv,OIdAj,FkXYR,KIQI) {" fullword ascii
    $s2  = "var RU = true  , EjkR = EYS[7] + EYS[9] + EYS[11];" fullword ascii
    $s3  = "return RKjWANc[0] + RKjWANc[2] + RKjWANc[4] + \".F\" + RKjWANc[7] + RKjWANc[9] + RKjWANc[12] + RKjWANc[14];" fullword ascii
    $s4  = "var RKjWANc = \"Sc WcKrrbc r KkrujzdRB ipting HzyyOam bLI ile RuLPIBMDvmnuWi System xQ SrMGe Obj EEhmJk ect wmtIYgi\".split(\" " ascii
    $s5  = "var EYS = (\"2.XMLHTTP BnGzveF AIFRq XML ream St BdmYBFJn AD tlvswUG O DkSX D\").split(\" \");" fullword ascii
    $s6  = "jLfid.open(Ububl,qJPDg,false);" fullword ascii
    $s7  = "function XBNk(YHyqM) {" fullword ascii
    $s8  = "function qPdu(QheIK) {" fullword ascii
    $s9  = "return dt.ExpandEnvironmentStrings(KiYCy[6]+KiYCy[7]+KiYCy[8]);" fullword ascii
    $s10 = "if (XtQuA > 163976-356){return true;} else {return false;}" fullword ascii
    $s11 = "return nzGEM;" fullword ascii
    $s12 = "function KbfEatn(NTUA) {" fullword ascii
    $s13 = "if (((new Date())>0,743856888)) {" fullword ascii
    $s14 = "if (lQNOU == 1162-962){return true;} else {return false;}" fullword ascii
    $s15 = "return new ActiveXObject(kdKWZu);" fullword ascii
    $s16 = "fPu = K; break; " fullword ascii
    $s17 = "function ejrct(kdKWZu) {" fullword ascii
    $s18 = "function sjOf(qejrb) {" fullword ascii
    $s19 = "if(K>=d.length) {break;}" fullword ascii
    $s20 = "function wgDh(XtQuA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}