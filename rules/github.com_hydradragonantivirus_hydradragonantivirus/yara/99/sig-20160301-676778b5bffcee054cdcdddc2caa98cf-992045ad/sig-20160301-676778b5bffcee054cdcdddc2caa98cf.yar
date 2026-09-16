rule sig_20160301_676778b5bffcee054cdcdddc2caa98cf {
  meta:
    description = "datamaliciousorder - file 20160301_676778b5bffcee054cdcdddc2caa98cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09fe185e732a20025d6b5c5fd4f910675ae3b605966bba4cc791c6ac69da7cf5"

  strings:
    $s1 = "intellectMass = (\"i\" + \"\\u006d\\u0070\\u006fr\\u0074\", \"e\\u0066\" + \"fect\", function String.prototype.aquariumPosition(" ascii
    $s2 = "while (evolutionFirm[(\"\\u0072\\u0065\\u0061\" + \"d\" + \"\\u0079\" + \"s\\u0074\\u0061\\u0074\\u0065\")] < ((0 / 13) | (164 /" ascii
    $s3 = "switchGame = (((183, 235, 0) | (1 & 1)), this);" fullword ascii
    $s4 = "} catch (regulateVacant) {};" fullword ascii

  condition:
    uint16(0) == 0x7773 and
    all of them
}