rule sig_20160224_699b18ec87584e3c6fe10f4bfaf472e3 {
  meta:
    description = "datamaliciousorder - file 20160224_699b18ec87584e3c6fe10f4bfaf472e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05352d3f200bac22801e1aeb887bc9b1bb2084060775e57f661aaeca85a61796"

  strings:
    $s1 = "\\u0063\\u0061l\\u002E\\u0068\\u0075\\u002Fm\\u0065\\u0064i\\u0061/8\\u0037\\u00687\\u0035\\u0034', false);" fullword ascii
    $s2 = "var kSItakK= this['\\u0041\\u0063\\u0074i\\u0076\\u0065X\\u004F\\u0062jec\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}