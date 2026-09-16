rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26f6211b03ebf0946d78c21caeb9a1ea09def170bcb7835d01ca0d6fbc3e91d6"

  strings:
    $s1 = "TO RESOLVE A DISPUTE WITH THE MA NUFA CTURER OR INSTALLER, OR`" fullword ascii
    $s2 = "/your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}