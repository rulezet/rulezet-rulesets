rule sig_20160914_126e6fde050550d68ff0b7fb1d42b954 {
  meta:
    description = "datamaliciousorder - file 20160914_126e6fde050550d68ff0b7fb1d42b954.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba236e9baedde316957e22453629784bab12ae0ffe6ca894de64eeab7ec399e"

  strings:
    $s1  = "var kojulbejo = new Function(olhywnazbatr[\"ensyvadu\"] + disedpovwa + jomvyzaxk + teryrnawq[\"fifkoks\"] + ajkyped5() + nzanalg" ascii
    $s2  = "var ecybhatzu = new Array('ur', 'mi', 'at', 'es', 'ewi', 'bnih', 'mbekg', 'pdewg', 'o', 'qif', 'iffa', 'y', 'lpo', 'ka', WScript" ascii
    $s3  = "var ecybhatzu = new Array('ur', 'mi', 'at', 'es', 'ewi', 'bnih', 'mbekg', 'pdewg', 'o', 'qif', 'iffa', 'y', 'lpo', 'ka', WScript" ascii
    $s4  = "var kojulbejo = new Function(olhywnazbatr[\"ensyvadu\"] + disedpovwa + jomvyzaxk + teryrnawq[\"fifkoks\"] + ajkyped5() + nzanalg" ascii
    $s5  = "return runirzajwez9;" fullword ascii
    $s6  = "return abpulo;" fullword ascii
    $s7  = "return lysnepsusewg;" fullword ascii
    $s8  = "return ylamopp2;" fullword ascii
    $s9  = "return ohurixxip5;" fullword ascii
    $s10 = "function vyckoweqx() {" fullword ascii
    $s11 = "return altugevuvi;" fullword ascii
    $s12 = "return obibelfyb6;" fullword ascii
    $s13 = "return usoxzobd4;" fullword ascii
    $s14 = "function pahmyxqy2() {" fullword ascii
    $s15 = "function afcujo1() {" fullword ascii
    $s16 = "return wozerfobig;" fullword ascii
    $s17 = "function ulketewqo() {" fullword ascii
    $s18 = "function erwalymu4() {" fullword ascii
    $s19 = "function tewwy6() {" fullword ascii
    $s20 = "return ajcuticemh2;" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}