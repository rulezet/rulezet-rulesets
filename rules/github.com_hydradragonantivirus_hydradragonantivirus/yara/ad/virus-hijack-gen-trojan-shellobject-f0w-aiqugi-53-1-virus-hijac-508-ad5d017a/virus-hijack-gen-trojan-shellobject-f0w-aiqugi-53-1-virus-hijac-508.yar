import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_53_1_Virus_Hijac_508 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_53_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bcd833092ac63f9b6613c5e323c7420a4638a923cdc1cc4c9469d0de801dbaa"
    hash2       = "99f5cd97d11c2075b2195b455c310e6d141e56493fbef9f33ad4b902be2e908a"

  strings:
    $x1  = "5/17/2021 3:25:46 - PFRO Error: \\??\\C:\\Windows\\system32\\spool\\V4Dirs\\9A7DC3A8-15D6-4495-B09B-AB6C19C98408\\94766af2.gpd, " wide
    $s2  = "3/15/2021 6:36:35 - PFRO Error: \\??\\C:\\Program Files\\Google\\Chrome, |delete operation|, 0xc0000101" fullword wide
    $s3  = "3/15/2021 6:36:35 - PFRO Error: \\??\\C:\\Program Files\\Google, |delete operation|, 0xc0000101" fullword wide
    $s4  = "5/18/2021 1:5:34 - PFRO Error: \\??\\C:\\Program Files (x86)\\Mozilla Firefox\\tobedeleted\\moz4ba528c2-b132-480a-8480-14a5bfcef" wide
    $s5  = "5/18/2021 1:5:34 - PFRO Error: \\??\\C:\\Program Files (x86)\\Mozilla Firefox\\tobedeleted\\, |delete operation|, 0xc0000034" fullword wide
    $s6  = "8/3/2021 6:30:8 - PFRO Error: \\??\\C:\\Program Files (x86)\\Microsoft\\Edge, |delete operation|, 0xc0000101" fullword wide
    $s7  = "8/3/2021 6:30:8 - PFRO Error: \\??\\C:\\Program Files (x86)\\Mozilla Firefox\\tobedeleted\\moz988840bf-5638-45aa-adde-f76b44d159" wide
    $s8  = "8/3/2021 6:30:8 - PFRO Error: \\??\\C:\\Program Files (x86)\\Mozilla Firefox\\tobedeleted\\, |delete operation|, 0xc0000034" fullword wide
    $s9  = "3/15/2021 6:36:35 - 2 Successful PFRO operations" fullword wide
    $s10 = "5/17/2021 3:25:46 - 9 Successful PFRO operations" fullword wide
    $s11 = "8/3/2021 6:30:8 - 6 Successful PFRO operations" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "895fbb56c02c3d2bca3125cef5da8730" and (1 of ($x*) and all of them)
    ) or (all of them)
}