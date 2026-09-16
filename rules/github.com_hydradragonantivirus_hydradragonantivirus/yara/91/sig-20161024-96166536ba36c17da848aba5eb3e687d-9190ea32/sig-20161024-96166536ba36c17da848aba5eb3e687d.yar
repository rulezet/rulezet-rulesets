rule sig_20161024_96166536ba36c17da848aba5eb3e687d {
  meta:
    description = "datamaliciousorder - file 20161024_96166536ba36c17da848aba5eb3e687d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1cf4153556b56fc96ebb8173379c05585e501a0343b977802843fee4782819f"

  strings:
    $s1 = "} while (un++ < dm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}