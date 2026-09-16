rule sig_20161024_fe8b62add454531a75bfeb631ea70fa3 {
  meta:
    description = "datamaliciousorder - file 20161024_fe8b62add454531a75bfeb631ea70fa3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8d5e96b54874bb26035585f890f489dca095ca4f449a9076928756dded82c37"

  strings:
    $s1 = "} while (tu0++ < od);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}