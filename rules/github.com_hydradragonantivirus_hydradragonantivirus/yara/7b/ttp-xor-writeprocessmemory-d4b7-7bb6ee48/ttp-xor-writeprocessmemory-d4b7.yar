rule TTP_XOR_WriteProcessMemory_d4b7 {
  strings:
    $key_d4b7 = { 83 c5 [2] b1 e7 [2] b7 d2 [2] 99 d2 [2] a6 ce }

  condition:
    any of them
}