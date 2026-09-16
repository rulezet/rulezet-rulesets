rule sig_20160303_e3a65d6c0ad78740973cebbfd8e2522a {
  meta:
    description = "datamaliciousorder - file 20160303_e3a65d6c0ad78740973cebbfd8e2522a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adaf460e6df37e8e2f0ee7fca69d768cfc032aca1221cb5739643bca57afb585"

  strings:
    $s1 = "while (dictionShock[voltEnergy + sexualPrivate] < (0 | 2) * (([!+[] + !+[]]))) {" fullword ascii
    $s2 = "collectRuin = (((3 * 2 + 1) + (30 & 31)), (((1 & 0) ^ (([+[]]))), this));" fullword ascii
    $s3 = "autonomousCorporation = (function String.prototype.arcticLexicon() {" fullword ascii
    $s4 = "} catch (historyAmpere) {};" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    all of them
}