rule sig_20160301_b047d54c46fb34f94ad856411ac1d985 {
  meta:
    description = "datamaliciousorder - file 20160301_b047d54c46fb34f94ad856411ac1d985.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afdc5ae61216f8d653bdcefa8c6357ce61412c51eeed54c5eb58e267a6673077"

  strings:
    $s1 = "\\u0072\\u0069p\" + \"t\")][(\"\\u0073y\\u006eon\\u0079\" + \"\\u006d\", function String.prototype.distanceMatch() {" fullword ascii
    $s2 = "while(directorVulgar[(\"ch\\u0061\\u0072\\u006d\", \"\\u0072ea\\u0064\" + \"\\u0079\\u0073ta\\u0074\" + \"\\u0065\")] < (2 * (([" ascii
    $s3 = "while(directorVulgar[(\"ch\\u0061\\u0072\\u006d\", \"\\u0072ea\\u0064\" + \"\\u0079\\u0073ta\\u0074\" + \"\\u0065\")] < (2 * (([" ascii
    $s4 = "fragmentTrophy = (((0 | 0) ^ (0 + 1)), this);" fullword ascii
    $s5 = "   fragmentTrophy[(\"ba\\u0072r\" + \"\\u0061\\u0063\\u006b\", \"d\\u0061te\", \"a\\u0067en\" + \"t\", \"\\u006de\\u0074\\u0061" ascii
    $s6 = "} catch(assortmentOrigin) {};" fullword ascii

  condition:
    uint16(0) == 0x7266 and
    all of them
}