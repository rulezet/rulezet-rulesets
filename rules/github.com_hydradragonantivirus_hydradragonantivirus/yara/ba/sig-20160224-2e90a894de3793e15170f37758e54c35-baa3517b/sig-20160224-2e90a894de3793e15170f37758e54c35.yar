rule sig_20160224_2e90a894de3793e15170f37758e54c35 {
  meta:
    description = "datamaliciousorder - file 20160224_2e90a894de3793e15170f37758e54c35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b7b9fcede4ad969997543c6fad4783603ba03b15b537ec14e17cfc06c3025db"

  strings:
    $s1 = "var VOTkxF= this['\\u0041\\u0063\\u0074\\u0069\\u0076\\u0065\\u0058\\u004Fbj\\u0065c\\u0074'];" fullword ascii
    $s2 = "4\\u0065\\u006D\\u002F\\u006Co\\u0067\\u0073\\u002F\\u0038\\u0037h75\\u0034', false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}