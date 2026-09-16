rule sig_20160309_ec4b6aa790804646b5bc6a1bf99f1d2c {
  meta:
    description = "datamaliciousorder - file 20160309_ec4b6aa790804646b5bc6a1bf99f1d2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3cd25988c1ba620ad62ad5ae34ce08f003ba19cc8432a518a69516f538d03c5"

  strings:
    $s1  = "var aS = true  , AnGo = Wnc[7] + Wnc[9] + Wnc[11];" fullword ascii
    $s2  = "var TGU = mfQt(AnGo + \"B.\" + Wnc[5]+(76952, Wnc[4]));" fullword ascii
    $s3  = "return PNQVfFT[0] + PNQVfFT[2] + PNQVfFT[4] + \".F\" + PNQVfFT[7] + PNQVfFT[9] + PNQVfFT[12] + PNQVfFT[14];" fullword ascii
    $s4  = "var Wnc = (\"2.XMLHTTP MzTkpXZ CgvHO XML ream St uJgepXWv AD EYmnWBK O gWlp D\").split(\" \");" fullword ascii
    $s5  = "svrzz.open(fDwjq,UzRie,false);" fullword ascii
    $s6  = "var PNQVfFT = \"Sc SUGPZrQ r lQsVwvjqJ ipting yhgAkKB rJN ile JCXjxKvndmIQYH System tU SYMHg Obj RxqZej ect eqPAykY\".split(\" " ascii
    $s7  = "return OWQP.responseBody;" fullword ascii
    $s8  = "function boPMdtdug(kjdlYHRdePw) {" fullword ascii
    $s9  = "return mkB.size;" fullword ascii
    $s10 = "function mfQt(dPUsA) {" fullword ascii
    $s11 = "return oCKal.status;" fullword ascii
    $s12 = "function mtKf(vFigE,IYuYx) {" fullword ascii
    $s13 = "function skKRLZQf(mkB) {" fullword ascii
    $s14 = "if(d>=f.length) {break;}" fullword ascii
    $s15 = "return ygxwryW(Ib,VXfWO[238-232]+VXfWO[550-543]+VXfWO[303-295]);" fullword ascii
    $s16 = "return zkJw.ExpandEnvironmentStrings(WPKgd);" fullword ascii
    $s17 = "return NqGHPYh" fullword ascii
    $s18 = "if (UXeBc > 172041-965){return true;} else {return false;}" fullword ascii
    $s19 = "function ELpQCPi(OWQP) {" fullword ascii
    $s20 = "return new ActiveXObject(AbQYBC);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}