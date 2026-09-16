import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au0WBJh_1_2_Virus_Hijac_281 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_30_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8W@aKuHmDp_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be392e900bd582aaddd212db7849e4d699343b2821ccfc0a1b6a343bc362ea45"
    hash2       = "18a62a390312cd75423d2bc8435f565378c589957512f2e77ae5ec0a678948ed"
    hash3       = "c91b4f6289bcf4a27a79e563b6aa4bc96e25e5c1cec871b2a7b0657b6181d411"
    hash4       = "9038b17b077587c80a22de64dc54ea29055472524a8ad9d161d8d363ce1d7c95"
    hash5       = "37b95de29e802dd755bba6a1d82cabcf783670a3817b67ac9da3149f824b5acc"
    hash6       = "637667bf1d4fbb999c2e23a5a6e01007d88d6f10d6b6a6a740cae2c83704c2cb"

  strings:
    $s1 = "Common::IsOnlyCentennialOfficeTemplateRegistered - RegCreateKeyEx returned = %1%." fullword wide
    $s2 = "Common::IsOnlyCentennialOfficeTemplateRegistered - RegQueryInfoKey returned = %1%. cValues = %2%" fullword wide
    $s3 = "Common::IsOnlyCentennialOfficeTemplateRegistered() - Entering." fullword wide
    $s4 = "Common::IsOnlyCentennialOfficeTemplateRegistered - RegEnumValue returned = %1%. valueName = %2%" fullword wide
    $s5 = "Common::IsOnlyCentennialOfficeTemplateRegistered - onlyCentennialOfficeTemplateRegistered = %1%." fullword wide
    $s6 = "%TEMP%\\Microsoft\\UEV\\LocalSyncFolder\\SettingsPackages" fullword wide
    $s7 = "Common::IsOnlyCentennialOfficeTemplateRegistered()" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26726e2f78645ad9c311f13886afe185" and (all of them)
    ) or (all of them)
}