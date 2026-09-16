rule Trojan_Danger_Trojan_GenericKD_67166905_386_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_386_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99a128f975ea98f7646b26ba443b9a0a95a32c03d3deed324c293ce870057767"

  strings:
    $s1 = "Umust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}