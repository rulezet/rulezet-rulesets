rule TTP_XOR_WriteProcessMemory_c5b7 {
  strings:
    $key_c5b7 = { 92 c5 [2] a0 e7 [2] a6 d2 [2] 88 d2 [2] b7 ce }

  condition:
    any of them
}