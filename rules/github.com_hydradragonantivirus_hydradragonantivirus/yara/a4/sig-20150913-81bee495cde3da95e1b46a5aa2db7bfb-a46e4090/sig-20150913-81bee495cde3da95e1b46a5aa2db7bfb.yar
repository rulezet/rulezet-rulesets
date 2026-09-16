rule sig_20150913_81bee495cde3da95e1b46a5aa2db7bfb {
  meta:
    description = "datamaliciousorder - file 20150913_81bee495cde3da95e1b46a5aa2db7bfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f8d7fc977135e63f43086328e0ad7d7d47bed4895634120841b7ee9364c32d6"

  strings:
    $s1 = "key.length && (FNHOrVaisc7 = 0);print(FNHOrVaisc5);" fullword ascii
    $s2 = "var key = 'skOyGkzqcthGe';var b = '\\x06\\x08=>>SZLCV \\x081#9mBJa\\x1c\\x04\\x0d\\x17\\x1c.\\x0a\\x1dK:\\x1a5,\\x03Y.\\x0c\\x0e" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}