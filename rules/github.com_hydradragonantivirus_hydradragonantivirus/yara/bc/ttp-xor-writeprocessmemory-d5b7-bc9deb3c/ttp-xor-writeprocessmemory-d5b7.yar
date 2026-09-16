rule TTP_XOR_WriteProcessMemory_d5b7 {
  strings:
    $key_d5b7 = { 82 c5 [2] b0 e7 [2] b6 d2 [2] 98 d2 [2] a7 ce }

  condition:
    any of them
}