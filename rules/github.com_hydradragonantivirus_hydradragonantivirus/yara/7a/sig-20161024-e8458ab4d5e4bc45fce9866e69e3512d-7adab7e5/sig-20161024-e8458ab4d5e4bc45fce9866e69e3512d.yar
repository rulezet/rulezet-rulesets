rule sig_20161024_e8458ab4d5e4bc45fce9866e69e3512d {
  meta:
    description = "datamaliciousorder - file 20161024_e8458ab4d5e4bc45fce9866e69e3512d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95ac120612d663ad6083c6508089ce978acfc14db3fab999ea64f7e3bf365d18"

  strings:
    $s1 = "} while (je++ < gr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}