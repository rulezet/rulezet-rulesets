rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_256 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_256.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b82aee7c2d90381eeb12eb4a1c60427354428666ff8ef2180dcb320c860b1dba"

  strings:
    $s1 = "]prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}