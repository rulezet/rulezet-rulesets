rule Virus_Hijack_Backdoor_Hangup_B_57_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94d60a76073cd314e2bc2fb74199e20bcd87046295565cdc017f552455e6d027"

  strings:
    $s1 = "PDF Reader for Windo" fullword wide
    $s2 = "PDFLogic Corporation                                        " fullword wide
    $s3 = " 2005-2021 PDFLogic Corporation                                                          " fullword wide
    $s4 = "PDF Reader for Windows 7 Setup                              " fullword wide
    $s5 = "PDF Reader for Windows                                      " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}