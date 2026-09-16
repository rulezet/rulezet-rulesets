rule TTP_XOR_WriteProcessMemory_c6b7 {
  strings:
    $key_c6b7 = { 91 c5 [2] a3 e7 [2] a5 d2 [2] 8b d2 [2] b4 ce }

  condition:
    any of them
}