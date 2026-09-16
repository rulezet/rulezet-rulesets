rule sig_20160830_dc7996ca8b565bb59d0fbf102c0701e2 {
  meta:
    description = "datamaliciousorder - file 20160830_dc7996ca8b565bb59d0fbf102c0701e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "016367e0a3c1dd0f9cc7ab3eeee88960c1e3b0b97853803eb87e8c8e94e82f25"

  strings:
    $s1 = "split(\" \");" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}