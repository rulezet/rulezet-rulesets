rule Virus_Hijack_Backdoor_Hangup_B_190 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_190.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc5219d80cd29471aa8e6420a58199c90332b1878472273963287b9406aaa352"

  strings:
    $s1 = "Y-the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}