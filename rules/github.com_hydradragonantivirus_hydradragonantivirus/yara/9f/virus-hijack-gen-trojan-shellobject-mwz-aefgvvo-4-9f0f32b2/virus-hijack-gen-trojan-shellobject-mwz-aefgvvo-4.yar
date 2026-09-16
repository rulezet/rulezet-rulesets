rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5af84a62f6452945e9c34d419291d53ae7d4fd8d0052a56605178d03825e05b5"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}