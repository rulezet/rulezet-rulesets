rule case25_miners_shared {
  meta:
    description = "miners - file shared"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-05"
    hash1       = "9e69143530f6ccb30f813f3d9f0b5dfb51779999dcfe06784d2720ad057d8316"

  strings:
    $s1 = "2526272829" ascii  
    $s2 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
    $s3 = "RkeyedWo" fullword ascii
    $s4 = "failures" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 1000KB and
      (all of them)
    ) or (all of them)
}