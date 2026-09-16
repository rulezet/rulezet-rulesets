rule VirusShareTrojanPWSSiggen33692 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSSiggen33692.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77cd4154f0e95ecc46fa5c01f90754d4845a4d0a231634046fc7c3ae3b82a251"

  strings:
    $s1 = "Unreeling" fullword ascii
    $s2 = "Thinking Interface Inc.1" fullword ascii
    $s3 = "yARk>|" fullword ascii
    $s4 = "PaSt$|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}