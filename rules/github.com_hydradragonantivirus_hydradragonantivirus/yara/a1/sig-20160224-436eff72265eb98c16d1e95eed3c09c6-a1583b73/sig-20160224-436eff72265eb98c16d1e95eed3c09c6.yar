rule sig_20160224_436eff72265eb98c16d1e95eed3c09c6 {
  meta:
    description = "datamaliciousorder - file 20160224_436eff72265eb98c16d1e95eed3c09c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3fce7b15ff423a1cf2f54632a330ac675ed5c389a936a5c52c27ef1765521d7"

  strings:
    $s1 = "var DGhvin= this['\\u0041ct\\u0069\\u0076eX\\u004F\\u0062j\\u0065\\u0063t'];" fullword ascii
    $s2 = "u0063\\u0061\\u006C\\u002E\\u0068\\u0075\\u002F\\u006D\\u0065\\u0064\\u0069\\u0061/\\u00387\\u0068\\u0037\\u0035\\u0034', false)" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}