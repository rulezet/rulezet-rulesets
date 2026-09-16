rule sig_20160314_6f2c435a969c218dd4066ce8520645a2 {
  meta:
    description = "datamaliciousorder - file 20160314_6f2c435a969c218dd4066ce8520645a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca8aa589fcab14391648a1867ec69079025d5213d97f4b307d460f4e8143096"

  strings:
    $s1  = "var QW = true  , GwTa = JQb[7] + JQb[9] + JQb[11];" fullword ascii
    $s2  = "return fepLmWM[0] + fepLmWM[2] + fepLmWM[4] + \".F\" + fepLmWM[7] + fepLmWM[9] + fepLmWM[12] + fepLmWM[14];" fullword ascii
    $s3  = "var fepLmWM = \"Sc Wndvdqx r xrwzKSDND ipting MHpGjkB oOP ile xcYBPlQgiKVhCC System Gq sVQSA Obj ZFTDKO ect xwNBGIO IQaUi\".spli" ascii
    $s4  = "aCHHT.open(VcPhJ,NsYBt,false);" fullword ascii
    $s5  = "var JQb = (\"2.XMLHTTP oljNLiR bQjaF XML ream St powIgMWS AD uNxwHlj O RNub D\").split(\" \");" fullword ascii
    $s6  = "var fepLmWM = \"Sc Wndvdqx r xrwzKSDND ipting MHpGjkB oOP ile xcYBPlQgiKVhCC System Gq sVQSA Obj ZFTDKO ect xwNBGIO IQaUi\".spli" ascii
    $s7  = "function tTSfqrmC(nJz) {" fullword ascii
    $s8  = "return NLJumM.position=235-235;" fullword ascii
    $s9  = "return new ActiveXObject(cpFPoU);" fullword ascii
    $s10 = "if (M >= SzZuP.length) {break;}" fullword ascii
    $s11 = "return mfTlx;" fullword ascii
    $s12 = "return GgyV.ExpandEnvironmentStrings(vZUjQ);" fullword ascii
    $s13 = "return sgGO.responseBody;" fullword ascii
    $s14 = "if(G>=g.length) {break;}" fullword ascii
    $s15 = "function vhozxCDJl(flnkWrkiAUN) {" fullword ascii
    $s16 = "function KbEQnoux() {" fullword ascii
    $s17 = "function cugc(aCHHT,NsYBt,VcPhJ) {" fullword ascii
    $s18 = "return nJz.size;" fullword ascii
    $s19 = "function esOTS(NLJumM) {" fullword ascii
    $s20 = "if (rFapm == 1144-944){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}