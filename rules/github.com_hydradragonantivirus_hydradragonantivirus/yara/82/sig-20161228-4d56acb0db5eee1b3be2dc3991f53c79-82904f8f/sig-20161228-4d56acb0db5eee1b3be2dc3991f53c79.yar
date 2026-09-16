rule sig_20161228_4d56acb0db5eee1b3be2dc3991f53c79 {
  meta:
    description = "datamaliciousorder - file 20161228_4d56acb0db5eee1b3be2dc3991f53c79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76bd3305496fed9074a41b4c2dc1c74008cd607a742daaccafeff8faf7ba8e74"

  strings:
    $s1 = "if (['vj', 3, 2, 8, 1, 'zte', 'gh', 3, 'eqt', 'jo', 6, 'ojv', 4, 1, 1, 'gf', 'e', 'is', new Function(['ijh', 'ne', 4, 'd', 1, 'o" ascii
    $s2 = "omuvbyfd0 = [this][0][[2, 6, 'omr', 8, 'wv', 9, 'erb', 'slu', 'a', 2, 2, 6, 'yd', 'g', 'ps', 1, ylarmulyhkupedaxekrigvuhyz, 'ur'" ascii
    $s3 = "if (['vj', 3, 2, 8, 1, 'zte', 'gh', 3, 'eqt', 'jo', 6, 'ojv', 4, 1, 1, 'gf', 'e', 'is', new Function(['ijh', 'ne', 4, 'd', 1, 'o" ascii
    $s4 = "omuvbyfd0 = [this][0][[2, 6, 'omr', 8, 'wv', 9, 'erb', 'slu', 'a', 2, 2, 6, 'yd', 'g', 'ps', 1, ylarmulyhkupedaxekrigvuhyz, 'ur'" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}