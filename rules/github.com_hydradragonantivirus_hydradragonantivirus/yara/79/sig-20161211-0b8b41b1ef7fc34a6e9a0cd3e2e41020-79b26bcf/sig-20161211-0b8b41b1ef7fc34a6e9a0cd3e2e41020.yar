rule sig_20161211_0b8b41b1ef7fc34a6e9a0cd3e2e41020 {
  meta:
    description = "datamaliciousorder - file 20161211_0b8b41b1ef7fc34a6e9a0cd3e2e41020.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12a00b5c52b55cb06eef7eeb1ec9cc7e04c411fb6ead64ca6322e5b4cef74a7f"

  strings:
    $s1 = "if ([new Function([oxuq, 'e', 'r', 'zz'][0] + [qircihz, 'u', 'e', 'a'][0] + ['m', blulaxta, 'u'][1] + ['e', osugy][1] + ['ww', u" ascii
    $s2 = "if ([new Function([oxuq, 'e', 'r', 'zz'][0] + [qircihz, 'u', 'e', 'a'][0] + ['m', blulaxta, 'u'][1] + ['e', osugy][1] + ['ww', u" ascii
    $s3 = "uckarfu0 = this[['e', ikubj][1] + ['a', imaj, 'bt'][1] + [yhopyc, 'y'][0] + [rhoha, 'n'][0]];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}