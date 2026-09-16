rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_668 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_668.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e2c0dfa035a9b1db5f3aaa3d1679d21bf5b6f7a72c06acddc071ac73ae44d4e"

  strings:
    $s1 = "? are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}