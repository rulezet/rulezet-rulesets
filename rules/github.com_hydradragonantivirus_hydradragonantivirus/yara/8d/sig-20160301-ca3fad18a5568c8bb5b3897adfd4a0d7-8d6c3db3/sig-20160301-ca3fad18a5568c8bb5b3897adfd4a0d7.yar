rule sig_20160301_ca3fad18a5568c8bb5b3897adfd4a0d7 {
  meta:
    description = "datamaliciousorder - file 20160301_ca3fad18a5568c8bb5b3897adfd4a0d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cb4348b6ff694931d6368947af729782b965cce7993db6a79ccdf29685920a"

  strings:
    $s1 = "while (maskRepublic[(\"\\u0062\\u0069n\\u0061\\u0072y\", \"\\u0061\\u0064\\u0065q\\u0075\\u0061\\u0074\\u0065\", \"\\u0064ec\\u0" ascii
    $s2 = "stationPass = (2 * (93 / 31) * (47 & 47), this);" fullword ascii
    $s3 = "while (maskRepublic[(\"\\u0062\\u0069n\\u0061\\u0072y\", \"\\u0061\\u0064\\u0065q\\u0075\\u0061\\u0074\\u0065\", \"\\u0064ec\\u0" ascii
    $s4 = "0065ra\\u0074i\\u0076e\", function String.prototype.confidentialPresident() {" fullword ascii
    $s5 = "} catch (absorbButterfly) {};" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    all of them
}