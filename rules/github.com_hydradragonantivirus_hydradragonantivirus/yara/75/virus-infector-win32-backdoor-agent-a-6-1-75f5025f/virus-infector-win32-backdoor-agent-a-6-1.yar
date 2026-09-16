rule Virus_Infector_Win32_Backdoor_Agent_A_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Backdoor.Agent.A_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e4e1a933da533235ca02ff69e0b379ef4a182a06e39ab13303bfbe3c406cca"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}