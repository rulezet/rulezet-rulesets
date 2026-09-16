rule TTP_XOR_WriteProcessMemory_a5b7 {
  strings:
    $key_a5b7 = { f2 c5 [2] c0 e7 [2] c6 d2 [2] e8 d2 [2] d7 ce }

  condition:
    any of them
}