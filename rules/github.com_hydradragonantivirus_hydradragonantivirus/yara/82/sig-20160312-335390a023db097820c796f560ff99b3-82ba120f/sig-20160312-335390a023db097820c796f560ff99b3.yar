rule sig_20160312_335390a023db097820c796f560ff99b3 {
  meta:
    description = "datamaliciousorder - file 20160312_335390a023db097820c796f560ff99b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b4d0de06c56f6bc0e381b8cba5de2c1e4a82aa303c61c3aee8bed53ee93b98"

  strings:
    $s1  = "var nE = true  , zKjh = sGt[7] + sGt[9] + sGt[11];" fullword ascii
    $s2  = "return PLvyasG[0] + PLvyasG[2] + PLvyasG[4] + \".F\" + PLvyasG[7] + PLvyasG[9] + PLvyasG[12] + PLvyasG[14];" fullword ascii
    $s3  = "vcICt.open(WbCRT,oAZGh,false);" fullword ascii
    $s4  = "function jRUn(yBQxW,kUZRv) {" fullword ascii
    $s5  = "var sGt = (\"2.XMLHTTP uBGrBHG fsfup XML ream St vKcLhhVq AD ANQQbge O yVmr D\").split(\" \");" fullword ascii
    $s6  = "var PLvyasG = \"Sc wJXRrkt r zNQjDuGDQ ipting ouyOnqT FWG ile LZCmpriwpDQydO System mw lYeYA Obj xNuGCr ect PfOlwlU\".split(\" " ascii
    $s7  = "return zPxuT;" fullword ascii
    $s8  = "function yTCeGxuL(Hxb) {" fullword ascii
    $s9  = "return sxhilk.position=408-408;" fullword ascii
    $s10 = "function iKTL(ftqYf) {" fullword ascii
    $s11 = "return vEDh.responseBody;" fullword ascii
    $s12 = "function WlQv(ErDNV) {" fullword ascii
    $s13 = "function XgnwlnC(OgHa,YqUGy) {" fullword ascii
    $s14 = "return new ActiveXObject(XFCHja);" fullword ascii
    $s15 = "function YmRz(FpYMo) {" fullword ascii
    $s16 = "return vRwNFBV" fullword ascii
    $s17 = "return OgHa.ExpandEnvironmentStrings(YqUGy);" fullword ascii
    $s18 = "if(y>=W.length) {break;}" fullword ascii
    $s19 = "if (ErDNV == 1194-994){return true;} else {return false;}" fullword ascii
    $s20 = "function TyIu(NZeGn) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}