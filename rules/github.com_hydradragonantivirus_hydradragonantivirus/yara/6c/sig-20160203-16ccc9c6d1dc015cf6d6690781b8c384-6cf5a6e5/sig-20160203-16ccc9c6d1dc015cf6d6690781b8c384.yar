rule sig_20160203_16ccc9c6d1dc015cf6d6690781b8c384 {
  meta:
    description = "datamaliciousorder - file 20160203_16ccc9c6d1dc015cf6d6690781b8c384.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f40ef1d5b4dc8993b770c6797ffe9dbd85a3c34938a3067adb002a49df385a88"

  strings:
    $s1  = " + ('RQg7N', '9X4uq', 'g7', '%'.split(\"\").reverse().join(\"\")) + '' ) + String ['f' + ('AQST', '2Mf9x', 'MLU', 'r') + 'o' + (" ascii
    $s2  = "n(\"\")) + '' , arguments[0], false);" fullword ascii
    $s3  = "function az32fD1yZ () {" fullword ascii
    $s4  = "''] = function() {" fullword ascii
    $s5  = "    var aFs9juHjo = new this['A' + ('3y', 'dCZ6ay', 'QeDN', 'c') + '' + ('a8O', 'bxjXz1', '9V', 't') + 'i' + ('Z6i', 'Iij', 'RNJ" ascii
    $s6  = "    var aoxbgC98M = new this['Ac' + ('aj', 'jlorN', 'eA6', 't') + 'i' + ('TV', 'LjuzK', 'Hk', 'v') + 'e' + ('6na', 'xuZ', 'QoiDJ" ascii
    $s7  = "    aoxbgC98M['on' + ('malOQc', 'dv9uu', '8Yu3n', 'r') + 'e' + ('UGhd', '7jSS5N', 'f93', 'a') + '' + ('PjQ', 'OlJWjd', 'H4', 'd'" ascii
    $s8  = "            var a941SxznG = new this['A' + ('C65S', '0b', 'vP', 'c') + '' + ('BR', 'KfP215', 'Fi', 't') + '' + ('Q9GiK', 'oPa', " ascii
    $s9  = "    var aoxbgC98M = new this['Ac' + ('aj', 'jlorN', 'eA6', 't') + 'i' + ('TV', 'LjuzK', 'Hk', 'v') + 'e' + ('6na', 'xuZ', 'QoiDJ" ascii
    $s10 = "            var a941SxznG = new this['A' + ('C65S', '0b', 'vP', 'c') + '' + ('BR', 'KfP215', 'Fi', 't') + '' + ('Q9GiK', 'oPa', " ascii
    $s11 = "        aoxbgC98M['op' + ('ua', 'elswun', 'SaioNc', 'e') + 'n']('GE' + ('ryU5m', 'eFNpuS', 'EH809F', 'T'.split(\"\").reverse().j" ascii
    $s12 = "    var aaZVfJtxu = aFs9juHjo['Ex' + ('R6K8', 'mBnpNK', 'jFA4', 'p') + '' + ('Y8K', 'd6PMws', 'sWry', 'a') + 'n' + ('q3bO', 'ZyZ" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}