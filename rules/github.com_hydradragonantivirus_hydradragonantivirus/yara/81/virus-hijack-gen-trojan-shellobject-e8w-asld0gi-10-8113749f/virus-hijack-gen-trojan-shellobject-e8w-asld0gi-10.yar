rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cde27ecf21695d6267f84b1af3a33e5650228490835f300c97d0dad710fb4d3b"

  strings:
    $s1 = "[Outlook " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}