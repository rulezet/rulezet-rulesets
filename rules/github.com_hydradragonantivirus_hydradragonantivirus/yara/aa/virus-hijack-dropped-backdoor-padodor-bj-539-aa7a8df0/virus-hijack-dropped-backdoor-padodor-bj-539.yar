rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_539 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_539.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152c01cbe74f44b28c15408af5ca3715368f4219da5e56e8787b0d303fcafad4"

  strings:
    $s1 = "&2prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}