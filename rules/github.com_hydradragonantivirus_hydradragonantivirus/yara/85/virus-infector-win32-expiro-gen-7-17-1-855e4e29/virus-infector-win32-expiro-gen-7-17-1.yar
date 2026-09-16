rule Virus_Infector_Win32_Expiro_Gen_7_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea20e058420cb93eab77af1a0d3f34f065dfed57581da4e1213cee64aae88c68"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}