rule sig_20160224_354158cf3d0603a5bf84e5992848106b {
  meta:
    description = "datamaliciousorder - file 20160224_354158cf3d0603a5bf84e5992848106b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fca1722fc54770c4eaea8b8a4ae582981d47e62aa38b36865a8da2dd9ab8dd66"

  strings:
    $s1 = "var KNtKuDb= this['\\u0041\\u0063ti\\u0076\\u0065\\u0058Ob\\u006Ae\\u0063\\u0074'];" fullword ascii
    $s2 = "u0063\\u007A\\u002Fs\\u0079\\u0073te\\u006D/\\u0063\\u0061ch\\u0065/\\u00387\\u0068\\u0037\\u00354', false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}