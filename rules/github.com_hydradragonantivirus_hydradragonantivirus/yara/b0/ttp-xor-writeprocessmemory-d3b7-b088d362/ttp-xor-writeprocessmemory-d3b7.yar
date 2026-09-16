rule TTP_XOR_WriteProcessMemory_d3b7 {
  strings:
    $key_d3b7 = { 84 c5 [2] b6 e7 [2] b0 d2 [2] 9e d2 [2] a1 ce }

  condition:
    any of them
}