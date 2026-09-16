import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_32_1_Virus_Hijac_243 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_32_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f022c8c56ef2a54f14ffa360f125a4e5f25541c08fdbb423291df116ecc35e4a"
    hash2       = "eebe64ee281bb927d94c41682164be53496f58a8bab12ee832ab254bd3a2aedf"
    hash3       = "59bec145960b3ed3d57eb6661ab4511c679ee84f9bacb80713e9ac9964d4d17e"

  strings:
    $s1  = "            <!-- see base\\manifests\\power\\client-overrides.txt to make changes to these policy values -->" fullword ascii
    $s2  = "            <!-- COMMON CLIENT POWER POLICY OVERRIDES BEGIN -->" fullword ascii
    $s3  = "            <!-- COMMON CLIENT POWER POLICY OVERRIDES END -->" fullword ascii
    $s4  = "            <!-- security descriptor for power settings --> " fullword ascii
    $s5  = "            <!-- core parking core override -->" fullword ascii
    $s6  = "            <!-- DO NOT EDIT OVERRIDES IN THIS SECTION BY HAND!!! -->" fullword ascii
    $s7  = "            <!-- system standby timeout -->" fullword ascii
    $s8  = "            <!-- hiberfile size -->" fullword ascii
    $s9  = "            <!-- core parking parked perf state -->" fullword ascii
    $s10 = "            <!-- perf state increase threshold -->" fullword ascii
    $s11 = "            <!-- core parking increase threshold -->" fullword ascii
    $s12 = "            <!-- core parking increase time -->" fullword ascii
    $s13 = "            <!-- perf boost policy -->" fullword ascii
    $s14 = "            <!-- perf state decrease policy -->" fullword ascii
    $s15 = "            <!-- perf state decrease threshold -->" fullword ascii
    $s16 = "            <!-- perf history count -->" fullword ascii
    $s17 = "            <!-- hibernate enabled -->" fullword ascii
    $s18 = "            <!-- hard disk power down timeout -->" fullword ascii
    $s19 = "            <!-- core parking max cores -->" fullword ascii
    $s20 = "            <!-- core parking decrease time -->" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "895fbb56c02c3d2bca3125cef5da8730" and (8 of them)
    ) or (all of them)
}