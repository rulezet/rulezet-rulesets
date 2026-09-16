rule sig_20160203_88f2e9822b6133f907105e41ed855bba {
  meta:
    description = "datamaliciousorder - file 20160203_88f2e9822b6133f907105e41ed855bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db9bb96492c6e8a2b2a78103422c9b4cd588df4b77ebb86221e2dd7eb6432b18"

  strings:
    $s1  = "B', 'e') + ''] = function() {" fullword ascii
    $s2  = "\"\")) + 'P%' ) + String ['f' + ('4aknNd', 'R1I', 'ydRvjn', 'r') + 'o' + ('F3jL', 'OdU6', '4Z4fjr', 'm') + '' + ('JTys', '6GDBZ'" ascii
    $s3  = "        aHy8gXvwp['o' + ('rPEt', 'zNQ', 'WLN', 'p') + 'e' + ('bEeNeU', '3Xc0Zo', 'lS', 'n') + '']('GET' , arguments[0], false);" fullword ascii
    $s4  = "function a3lxMBaRF () {" fullword ascii
    $s5  = "    var autd6E5LV = new this['Ac' + ('AbRI', 'riYeks', 'KoLkf8', 't') + '' + ('JzBpu', 'NZCr', 'cCiV', 'i') + '' + ('etYzV', 'kj" ascii
    $s6  = "    var arC9brpcs = autd6E5LV['E' + ('XGgk', 'sQjIiy', 'zRs', 'x') + 'p' + ('JT5ns', 'XKCU1y', 'rwU', 'a') + 'n' + ('MaI5T0', 'f" ascii
    $s7  = "            var a8GAz6N2u = new this['A' + ('S1dY9', '0lzuiW', 'Q53z', 'c') + '' + ('XJIQc', '15t', 'edLgqJ', 't') + '' + ('KLQ'" ascii
    $s8  = "    var aHy8gXvwp = new this['A' + ('XH', 'XZYGr', 'A6f', 'c') + '' + ('fzxtMH', '2qGO', 'uUZ', 't') + 'i' + ('WvzUuy', 'VTa2', " ascii
    $s9  = "    aHy8gXvwp['on' + ('WN', 'KHE', 'ky', 'r') + '' + ('qdqD', 'toAEZ', 'J81VHl', 'e') + 'a' + ('pI6', 'sOgE9', 'FyfSZS', 'd') + " ascii
    $s10 = "    var aHy8gXvwp = new this['A' + ('XH', 'XZYGr', 'A6f', 'c') + '' + ('fzxtMH', '2qGO', 'uUZ', 't') + 'i' + ('WvzUuy', 'VTa2', " ascii
    $s11 = "            var a8GAz6N2u = new this['A' + ('S1dY9', '0lzuiW', 'Q53z', 'c') + '' + ('XJIQc', '15t', 'edLgqJ', 't') + '' + ('KLQ'" ascii
    $s12 = "    var autd6E5LV = new this['Ac' + ('AbRI', 'riYeks', 'KoLkf8', 't') + '' + ('JzBpu', 'NZCr', 'cCiV', 'i') + '' + ('etYzV', 'kj" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}