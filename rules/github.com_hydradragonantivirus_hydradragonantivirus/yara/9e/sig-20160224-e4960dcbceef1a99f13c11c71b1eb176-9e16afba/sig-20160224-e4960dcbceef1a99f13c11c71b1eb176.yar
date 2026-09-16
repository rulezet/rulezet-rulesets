rule sig_20160224_e4960dcbceef1a99f13c11c71b1eb176 {
  meta:
    description = "datamaliciousorder - file 20160224_e4960dcbceef1a99f13c11c71b1eb176.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2037ae2d697110439af17cf80aa373e0a2e6c4b610fa67ad3667605db65dcd6"

  strings:
    $s1 = "87\\u0035\\u0034', false);" fullword ascii
    $s2 = "var lKefdE= this['\\u0041\\u0063t\\u0069\\u0076\\u0065X\\u004Fbj\\u0065\\u0063\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}