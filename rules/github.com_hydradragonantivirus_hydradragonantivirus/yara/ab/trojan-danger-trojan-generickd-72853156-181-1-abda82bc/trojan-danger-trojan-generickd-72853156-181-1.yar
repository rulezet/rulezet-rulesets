rule Trojan_Danger_Trojan_GenericKD_72853156_181_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_181_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5cdec08ca4017fc7eeea15addafd707c241b52e8f0f61e310b146abc337f1a"

  strings:
    $s1 = "aLMA%{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}