rule TTP_XOR_WriteProcessMemory_c7b7 {
  strings:
    $key_c7b7 = { 90 c5 [2] a2 e7 [2] a4 d2 [2] 8a d2 [2] b5 ce }

  condition:
    any of them
}