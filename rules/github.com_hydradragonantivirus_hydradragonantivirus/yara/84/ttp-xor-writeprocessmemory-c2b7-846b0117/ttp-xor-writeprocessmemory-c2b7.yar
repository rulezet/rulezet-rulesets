rule TTP_XOR_WriteProcessMemory_c2b7 {
  strings:
    $key_c2b7 = { 95 c5 [2] a7 e7 [2] a1 d2 [2] 8f d2 [2] b0 ce }

  condition:
    any of them
}