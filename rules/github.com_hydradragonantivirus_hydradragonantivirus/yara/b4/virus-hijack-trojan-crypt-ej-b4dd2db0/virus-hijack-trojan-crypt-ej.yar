rule Virus_Hijack_Trojan_Crypt_EJ {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Crypt.EJ.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecd8abbb3d319e1bd02c3a95af8e36e3999e97ca8dc0bae0c3ebb02362fad45e"

  strings:
    $s1 = "u#Hand" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}