rule TTP_XOR_WriteProcessMemory_a3b7 {
  strings:
    $key_a3b7 = { f4 c5 [2] c6 e7 [2] c0 d2 [2] ee d2 [2] d1 ce }

  condition:
    any of them
}