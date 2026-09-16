rule Trojan_Danger_Trojan_GenericKD_67166905_352_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_352_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bdb2fbe22f8dd0c24d817f3f289339787dc90f508d64ba40908f410202c851a"

  strings:
    $s1 = "'fmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}