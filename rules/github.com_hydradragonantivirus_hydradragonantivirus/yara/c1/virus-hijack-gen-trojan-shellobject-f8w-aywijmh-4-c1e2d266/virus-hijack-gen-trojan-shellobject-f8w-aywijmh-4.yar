rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4067467e63726b0bc7dc588eb8e4fd7bad1df179f138febb37cb4e7bff048c6f"

  strings:
    $s1 = "Qyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}