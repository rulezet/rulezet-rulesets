rule sig_20161024_58acd0fcd6252db745b1dd6c6e88ccee {
  meta:
    description = "datamaliciousorder - file 20161024_58acd0fcd6252db745b1dd6c6e88ccee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddad3ee9e3d44d110a04adca7cc87d10b3af68fd92b460585364b10ed08258d8"

  strings:
    $s1 = "} while (gr1++ < yh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}