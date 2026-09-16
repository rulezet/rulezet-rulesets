rule sig_20160525_7ade4c37128a2f74a29f0ee5115e1d49 {
  meta:
    description = "datamaliciousorder - file 20160525_7ade4c37128a2f74a29f0ee5115e1d49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a34d29853cdee0641ee6e8b1239e333a4e0464290a65f7f20e4d71bf7c791d00"

  strings:
    $s1 = "nark noitcnuf\\n;\"nepf6x\\\\\" = cthk rav\\n;\"56x\\\\07x\\\\y47x\\\\\" = rerednerk rav;};eixodl nruter{)eixodl(imk noitcnuf\\n" ascii
    $s2 = "loca rav" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}