rule sig_20160415_c2a6c8d278e1b32ea5cfe81e207ee7b2 {
  meta:
    description = "datamaliciousorder - file 20160415_c2a6c8d278e1b32ea5cfe81e207ee7b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f98edb459b96adf814163f6fe1396711ffb53da06a3bc16e79f2a2e2915f7b83"

  strings:
    $s1 = "\"'.substr(4),d43='8h.ra'.substr(1),a24='1ec884o *'.substr(6),c44='15d73b0tivi'.substr(7),y84='ea38ave'.substr(4),r44='b7ac\"Ple" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}