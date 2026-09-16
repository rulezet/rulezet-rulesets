rule sig_20160224_9c2e1cab3dae977447e8fbdfdb4281f8 {
  meta:
    description = "datamaliciousorder - file 20160224_9c2e1cab3dae977447e8fbdfdb4281f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86378795c6bdcc2b6b6b277153245109e351421766a31aadfe8f46abc59cff49"

  strings:
    $s1 = "002E\\u0063\\u007A/s\\u0079s\\u0074\\u0065m\\u002F\\u0063a\\u0063h\\u0065/\\u0038\\u0037\\u0068\\u00375\\u0034', false);" fullword ascii
    $s2 = "var teAbuCRo= this['A\\u0063t\\u0069\\u0076e\\u0058\\u004F\\u0062\\u006A\\u0065\\u0063t'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}