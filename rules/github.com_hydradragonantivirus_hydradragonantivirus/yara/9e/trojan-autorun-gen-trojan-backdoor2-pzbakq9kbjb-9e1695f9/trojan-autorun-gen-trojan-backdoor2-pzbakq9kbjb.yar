rule Trojan_Autorun_Gen_Trojan_Backdoor2__pZbaKq9kbjb {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.@pZbaKq9kbjb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "038136ed4e32ecd565fe5e922753bd8b03c2ac70d5f88ee0fbab70d6acd45563"

  strings:
    $s1 = ".?AV<lambda_1>@?1??GetCreateRequestFunction@RequestBroker@Http@Mso@@CA?AV?$function@$$A6A?AV?$TCntPtr@VIRequest@Http@Mso@@@Mso@@" ascii
    $s2 = ".?AV<lambda_1>@?1??GetCreateRequestFunction@RequestBroker@Http@Mso@@CA?AV?$function@$$A6A?AV?$TCntPtr@VIRequest@Http@Mso@@@Mso@@" ascii
    $s3 = "tTrouble with initialization of http context" fullword wide
    $s4 = "rdtsc hooked" fullword ascii
    $s5 = "rdtsc not hooked" fullword ascii
    $s6 = "dError reading the metadata categories" fullword wide
    $s7 = "Rich[s" fullword ascii
    $s8 = "@@A trace was discarded due to excessive length." fullword wide
    $s9 = ".Cannot serialize" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}