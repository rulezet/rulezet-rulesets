rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aOU94xe_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2c7b5eab3ddf4dc3d1881e35b6e1d4e235fb160698422a60299b347f1f3129e"

  strings:
    $s1 = "start %Process%" fullword ascii
    $s2 = "thread:\"" fullword ascii
    $s3 = "sleep:\"" fullword ascii
    $s4 = "type:\"" fullword ascii
    $s5 = "protocol:\"" fullword ascii
    $s6 = "speed:\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}