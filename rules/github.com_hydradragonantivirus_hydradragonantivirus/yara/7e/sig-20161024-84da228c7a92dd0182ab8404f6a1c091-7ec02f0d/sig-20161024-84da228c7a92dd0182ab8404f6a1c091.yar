rule sig_20161024_84da228c7a92dd0182ab8404f6a1c091 {
  meta:
    description = "datamaliciousorder - file 20161024_84da228c7a92dd0182ab8404f6a1c091.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e10e4163bcd81f400aa1ceec0190a4d03d7661bc1b940c52147ef8e3a51891e4"

  strings:
    $s1 = "} while (ue++ < zr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}