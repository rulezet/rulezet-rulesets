rule Virus_Hijack_Backdoor_Hangup_B_62_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7917b0047728ec387ecf5783bf4324efe20c5c732953ccfe2817bdd3bc72a908"

  strings:
    $s1  = "Memory page error" fullword ascii
    $s2  = "Exception handler tried to continue after non-continuable exception" fullword ascii
    $s3  = "Single step trap" fullword ascii
    $s4  = "Misaligned data access" fullword ascii
    $s5  = "Division by zero " fullword ascii
    $s6  = "Floating-point underflow (exponent too small)" fullword ascii
    $s7  = "Floating-point overflow (exponent to great)" fullword ascii
    $s8  = "Division by zero (floating-point)" fullword ascii
    $s9  = "Exception handler returned unknown value" fullword ascii
    $s10 = "Floating-point stack overflow or underflow" fullword ascii
    $s11 = "Inexact floating-point result" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}