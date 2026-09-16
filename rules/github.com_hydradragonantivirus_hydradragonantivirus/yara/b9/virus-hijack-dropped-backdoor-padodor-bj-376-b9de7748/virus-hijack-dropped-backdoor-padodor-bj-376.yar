rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_376 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_376.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ed1e9e5e2e3b3e34b17470db81c7eaad44320b0acacad7406129d281e04469"

  strings:
    $s1 = "}yEAst" fullword ascii
    $s2 = "<[D\\tuCAf{EAst" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}