rule sig_20161024_c2aa46b780a65c3e0f104bf476ba985f {
  meta:
    description = "datamaliciousorder - file 20161024_c2aa46b780a65c3e0f104bf476ba985f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e787e4f773e0d5e84d1bbc19aaf50c1bb59ea8929669aa6a850096b32084dbbe"

  strings:
    $s1 = "} while (ij++ < jr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}