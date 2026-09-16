rule _20170126_7ad814d6857dbb2cde5879caa2ab7d34_20170126_d72a6de9c724_2176 {
  meta:
    description = "datamaliciousorder - from files 20170126_7ad814d6857dbb2cde5879caa2ab7d34.js, 20170126_d72a6de9c72457b606f08f248c9950d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "741f5f1c651c76fd46642c12422b5d2bce84f42263a01bb4ccb811de304d7fcf"
    hash2       = "ec6545be81e9d886c2c4ff2ae3423abdf3f0727c181b987b85e98ee77802dc60"

  strings:
    $s1 = "return ['', '', '', '', \"Fi\"];" fullword ascii
    $s2 = "return [\"dy\", ''];" fullword ascii
    $s3 = "return ['', '', \"e\", '', ''];" fullword ascii
    $s4 = "return [\"ct\", ''];" fullword ascii
    $s5 = "return ['', \"ri\"];" fullword ascii
    $s6 = "return ['', '', '', '', \"Fu\"];" fullword ascii
    $s7 = "return ['', '', \"se\", ''];" fullword ascii
    $s8 = "return ['', '', '', \"pe\", ''];" fullword ascii
    $s9 = "return ['', '', \"GE\"];" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}