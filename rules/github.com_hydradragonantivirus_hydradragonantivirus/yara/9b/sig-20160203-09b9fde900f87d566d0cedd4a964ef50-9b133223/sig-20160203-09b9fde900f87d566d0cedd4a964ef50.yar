rule sig_20160203_09b9fde900f87d566d0cedd4a964ef50 {
  meta:
    description = "datamaliciousorder - file 20160203_09b9fde900f87d566d0cedd4a964ef50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d962c701d9aa29fcdf3a1a60a3cc43345bee6172221cebfdfbaa842537031544"

  strings:
    $s1  = "            var aHZBnazUx = new this['Ac' + ('q32J7v', 'XshbcE', 'CQu3', 't') + '' + ('tFhR', 'FEWDBP', 'ES', 'i') + 'v' + ('nJJ" ascii
    $s2  = "        aQVJxLHYl['o' + ('8Y', '4wwmuR', 'Kx', 'p') + '' + ('LWvIzO', 'TZ', '8JwKBz', 'e') + 'n']('GET' , arguments[0], false);" fullword ascii
    $s3  = "' + ('VEtu', 'EK', 'YturGT', 'n') + '' + ('X8r03', 'ZMbhDj', 'KRNpki', 'g') + 'e'] = function() {" fullword ascii
    $s4  = ")) + '' ) + String ['f' + ('bWin', 'xB', '1tc', 'r') + 'o' + ('7ez', 'AMS', '8N', 'm') + '' + ('Ypg', 'RHr', '0PXxrk', 'C') + 'h" ascii
    $s5  = "function aISrH1JcK () {" fullword ascii
    $s6  = "    var aQVJxLHYl = new this['Ac' + ('w8z', 'GmL', 'MRi', 't') + '' + ('UWW5', 'DClpt', 'GZRp', 'i') + 'v' + ('Gcxg', 'dDez', '5" ascii
    $s7  = "    aQVJxLHYl['on' + ('esE', '3c', 'r1', 'r') + 'e' + ('Wje0cF', 'LXu', 'lP', 'a') + 'd' + ('dd7', 'rm', '5vIiB', 'y') + '' + ('" ascii
    $s8  = "            var aHZBnazUx = new this['Ac' + ('q32J7v', 'XshbcE', 'CQu3', 't') + '' + ('tFhR', 'FEWDBP', 'ES', 'i') + 'v' + ('nJJ" ascii
    $s9  = "    var aRGgSqsCn = new this['Ac' + ('LN7sM', 'QXiKu', 't4Jb', 't') + 'i' + ('Lqpc', 'QhI', 'hM', 'v') + 'e' + ('yK', '0w', 'Rtc" ascii
    $s10 = "    var aRGgSqsCn = new this['Ac' + ('LN7sM', 'QXiKu', 't4Jb', 't') + 'i' + ('Lqpc', 'QhI', 'hM', 'v') + 'e' + ('yK', '0w', 'Rtc" ascii
    $s11 = "    var azZ0fGbYx = aRGgSqsCn['E' + ('DM', 'lzrytL', 'oavCt', 'x') + '' + ('nTYeE', 'HY', 'IrL', 'p') + '' + ('oUoK', 'PjXB', 'm" ascii
    $s12 = "    var aQVJxLHYl = new this['Ac' + ('w8z', 'GmL', 'MRi', 't') + '' + ('UWW5', 'DClpt', 'GZRp', 'i') + 'v' + ('Gcxg', 'dDez', '5" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}