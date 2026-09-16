rule sig_20160224_bc30f578659cae50265fab8bfd19e69d {
  meta:
    description = "datamaliciousorder - file 20160224_bc30f578659cae50265fab8bfd19e69d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d54dc1216736373f4995a55afd2d7f053e83cea986c880a2c782df3fa294e62"

  strings:
    $s1 = "2F\\u0072\\u0061\\u0074i\\u006E\\u0067\\u0073\\u002F\\u0038\\u0037\\u0068\\u0037\\u0035\\u0034', false);" fullword ascii
    $s2 = "var spkPwzK= this['\\u0041\\u0063\\u0074\\u0069\\u0076\\u0065\\u0058Ob\\u006A\\u0065\\u0063\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}