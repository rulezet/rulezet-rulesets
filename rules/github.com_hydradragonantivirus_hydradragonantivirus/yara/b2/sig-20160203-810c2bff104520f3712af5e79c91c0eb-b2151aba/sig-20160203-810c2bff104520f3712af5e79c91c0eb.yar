rule sig_20160203_810c2bff104520f3712af5e79c91c0eb {
  meta:
    description = "datamaliciousorder - file 20160203_810c2bff104520f3712af5e79c91c0eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3302339364a3260dd695b61c5abd0965c39e6f35ae8bd2757b9eb500bc31b4ce"

  strings:
    $s1  = "Xn', 'n') + '' + ('M1', 'GWK', 'SHMLx', 'g') + 'e'] = function() {" fullword ascii
    $s2  = ".split(\"\").reverse().join(\"\")) + '%' ) + String ['f' + ('Vi', '6hUkF', 'sjMC5', 'r') + 'o' + ('le', 'ekn', 'TP', 'm') + 'C' " ascii
    $s3  = "            var aKeygTZLh = new this['Ac' + ('anx1', 'tf', 'om', 't') + '' + ('PCD', 'jL', 'CjC', 'i') + 'v' + ('QdCoW', 'N6Ql'," ascii
    $s4  = "            var aKeygTZLh = new this['Ac' + ('anx1', 'tf', 'om', 't') + '' + ('PCD', 'jL', 'CjC', 'i') + 'v' + ('QdCoW', 'N6Ql'," ascii
    $s5  = " '' , arguments[0], false);" fullword ascii
    $s6  = "function aTwJcFRO7 () {" fullword ascii
    $s7  = "    var a8nyPzi07 = new this['Ac' + ('sln', 'Opq', 'tOMsN', 't') + '' + ('790O', 'VboWd', '4bCYv4', 'i') + '' + ('l8iLOL', 'AenL" ascii
    $s8  = "    a8nyPzi07['o' + ('e5M3G', '5ggz', '0VI', 'n') + 'r' + ('kw', '4K', 'yvNx', 'e') + '' + ('tvdH', '0LgA', 'xRqKRm', 'a') + '' " ascii
    $s9  = "    var aAS0gKPnh = new this['Ac' + ('dCSYR', 'eKq0', 'vv', 't') + '' + ('5Okf', '8G', 'MvD', 'i') + 'v' + ('yasMN', 'KEL', 'ocZ" ascii
    $s10 = "        a8nyPzi07['op' + ('Fj', '2SKw', '5296I', 'e') + 'n']('GE' + ('Wsc2', 'aLwYX', 'MhK', 'T'.split(\"\").reverse().join(\"\"" ascii
    $s11 = "    var aAS0gKPnh = new this['Ac' + ('dCSYR', 'eKq0', 'vv', 't') + '' + ('5Okf', '8G', 'MvD', 'i') + 'v' + ('yasMN', 'KEL', 'ocZ" ascii
    $s12 = "    var axsdrvErv = aAS0gKPnh['E' + ('fjkEiU', 'Pz4vW', 'UctivH', 'x') + '' + ('JPJ', 'z09', '3Xv', 'p') + '' + ('aFc', 'vLW0IR'" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}