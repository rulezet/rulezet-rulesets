rule sig_20160526_d1d0286e190e2f67609616ff4f66fafe {
  meta:
    description = "datamaliciousorder - file 20160526_d1d0286e190e2f67609616ff4f66fafe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b638145f65294d7b8f4fbb548468763391e2c355a661e256232146ef6f88f180"

  strings:
    $s1 = "BRET rav\\n;\"esoc6x\\\\c\" = p8sFMOYJZ rav\\n;\"gn56x\\\\c6x\\\\\" = z2vQWKELP rav\\n;\"86x\\\\t\" = h8fGRBSXG rav\\n;\"86x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}