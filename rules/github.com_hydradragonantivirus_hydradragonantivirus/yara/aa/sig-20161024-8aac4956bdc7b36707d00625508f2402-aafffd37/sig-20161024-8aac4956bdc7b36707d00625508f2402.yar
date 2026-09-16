rule sig_20161024_8aac4956bdc7b36707d00625508f2402 {
  meta:
    description = "datamaliciousorder - file 20161024_8aac4956bdc7b36707d00625508f2402.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60f714ff635bacd4e6ed2f9a5ccb91b6d7aea0db67f75b36d6654691ef679f57"

  strings:
    $s1 = "} while (vy++ < vi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}