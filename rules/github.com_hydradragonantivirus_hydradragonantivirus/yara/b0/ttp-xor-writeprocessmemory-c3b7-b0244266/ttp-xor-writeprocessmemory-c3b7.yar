rule TTP_XOR_WriteProcessMemory_c3b7 {
  strings:
    $key_c3b7 = { 94 c5 [2] a6 e7 [2] a0 d2 [2] 8e d2 [2] b1 ce }

  condition:
    any of them
}