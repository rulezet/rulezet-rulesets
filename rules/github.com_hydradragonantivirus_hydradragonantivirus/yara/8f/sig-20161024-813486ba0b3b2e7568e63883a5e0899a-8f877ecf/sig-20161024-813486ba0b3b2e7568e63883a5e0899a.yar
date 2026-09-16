rule sig_20161024_813486ba0b3b2e7568e63883a5e0899a {
  meta:
    description = "datamaliciousorder - file 20161024_813486ba0b3b2e7568e63883a5e0899a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fd85f964eecdd407beb7e7cf840e808a2e6105eb1300055cc67d860752e734a"

  strings:
    $s1 = "} while (vi++ < rz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}