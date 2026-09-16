rule VirusShareTrojanDownLoader4344000 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344000.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba0c33db9f52d9704bf190e3d2eff51d5b6d930cd679ca76ec2118d87519bbaa"

  strings:
    $s1 = ".Inno Setup Setup Data (5.5.0) (u)" fullword ascii
    $s2 = "HeRO{EjZ`" fullword ascii
    $s3 = "Dh(coLP" fullword ascii
    $s4 = "3:LacE" fullword ascii
    $s5 = "f!puDu" fullword ascii
    $s6 = "sWEp(`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}