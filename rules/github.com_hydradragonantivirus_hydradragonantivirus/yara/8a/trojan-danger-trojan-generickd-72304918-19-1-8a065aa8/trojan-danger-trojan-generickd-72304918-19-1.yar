rule Trojan_Danger_Trojan_GenericKD_72304918_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57219d1eae07b8e723633d4d62d382bd136effc4dd8dde489dc23662dfe7a2f"

  strings:
    $s1 = ":virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}