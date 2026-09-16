rule Trojan_Danger_Trojan_GenericKD_67166905_401_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_401_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c47d15d6c7a1290a333f1f2436ddfb5aefb8d27b021a0046dd5352312d6c6b"

  strings:
    $s1 = "dmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}