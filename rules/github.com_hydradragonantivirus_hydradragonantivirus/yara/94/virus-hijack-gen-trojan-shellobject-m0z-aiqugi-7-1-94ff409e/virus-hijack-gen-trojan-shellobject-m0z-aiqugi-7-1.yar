rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85dccc57928409b148720aedc86bae17281f0184916450ac102bb2730a9e40e2"

  strings:
    $s1 = "miner eth.exe" fullword wide
    $s2 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s3 = "miner eth" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}