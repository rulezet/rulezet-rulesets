rule sig_20160309_63f5e4eb53660cd073cb346a07dc483a {
  meta:
    description = "datamaliciousorder - file 20160309_63f5e4eb53660cd073cb346a07dc483a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a909d22e8756d94017792ca4571e5e18d355a79a3ae1088aa493dfc2f60aa397"

  strings:
    $s1  = "var xe = true  , ZDsS = PIF[7] + PIF[9] + PIF[11];" fullword ascii
    $s2  = "return JyTzXGb[0] + JyTzXGb[2] + JyTzXGb[4] + \".F\" + JyTzXGb[7] + JyTzXGb[9] + JyTzXGb[12] + JyTzXGb[14];" fullword ascii
    $s3  = "sdtrS.open(WmqKw,nelwt,false);" fullword ascii
    $s4  = "var JyTzXGb = \"Sc nOHGWaH r JJaFgfXrM ipting bLIyAwM xlY ile NgODxVrJeZROVM System vS gnprF Obj OBBMWi ect JgqXuHP\".split(\" " ascii
    $s5  = "var PIF = (\"2.XMLHTTP EOTXGaT lVwkn XML ream St xgEuaXDi AD mHwSiYE O nbXz D\").split(\" \");" fullword ascii
    $s6  = "function yraYljlG(szjek,SQSILP) {" fullword ascii
    $s7  = "function ItidnoWnE(AdEiNENheeT) {" fullword ascii
    $s8  = "function NsYftUjhk(xWHcW,oaMqh,bOYuO,uFxb) {" fullword ascii
    $s9  = "return ZExX.ExpandEnvironmentStrings(IJffE);" fullword ascii
    $s10 = "function ZzpK(yAWOm,IYADZ) {" fullword ascii
    $s11 = "function lcYnUarH(qXs) {" fullword ascii
    $s12 = "if(k>=e.length) {break;}" fullword ascii
    $s13 = "function KYEqfqk(ZExX,IJffE) {" fullword ascii
    $s14 = "function XjTpcIY(TrQX) {" fullword ascii
    $s15 = "return qXs.size;" fullword ascii
    $s16 = "function kgwS(yLJCP) {" fullword ascii
    $s17 = "function LvXw(zbdVX) {" fullword ascii
    $s18 = "function MHnw(xsFTW,OREiA) {" fullword ascii
    $s19 = "if (UulNY == 617-417){return true;} else {return false;}" fullword ascii
    $s20 = "kiC = k; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}