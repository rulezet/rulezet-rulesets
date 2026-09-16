rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_113_1_Virus_Hija_566 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_113_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d1b509451f00201266d1ca734cf8ae37fdeeedde7a1a4550e0750e9e3316a8"
    hash2       = "3112ee48980ee355e436b9f1f525b69c09d522fd26edd28acb64066bd24a57a0"
    hash3       = "660abb9fe016d15a4064be6ed8a9c3dddb3ae71c06d80f8b5e32d0c471fc1dc3"
    hash4       = "906c9e4e5ab33e9c806bf6d599c20c12a923b135167ae404a119876bfdae42ab"
    hash5       = "0020b5f10333813bb3ba921bf702cd6ec4f9f7631c53e948ca0710d14cd55e34"

  strings:
    $s1 = "WARNING: Failed to read the service id for re-registration 0x80070002" fullword ascii
    $s2 = "WARNING: Missing service entry in the backup data store; cleaning up" fullword ascii
    $s3 = "Default service for AU is {00000000-0000-0000-0000-000000000000}" fullword ascii
    $s4 = "Switching to hardware-verified ClientId." fullword ascii
    $s5 = "WARNING: failed to calculate prior restore point time with error 0x80070002; setting restore point" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}