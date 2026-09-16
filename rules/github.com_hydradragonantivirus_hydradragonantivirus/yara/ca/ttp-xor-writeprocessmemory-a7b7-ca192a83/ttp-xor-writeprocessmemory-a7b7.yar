rule TTP_XOR_WriteProcessMemory_a7b7 {
  strings:
    $key_a7b7 = { f0 c5 [2] c2 e7 [2] c4 d2 [2] ea d2 [2] d5 ce }

  condition:
    any of them
}