rule TTP_XOR_WriteProcessMemory_a0b7 {
  strings:
    $key_a0b7 = { f7 c5 [2] c5 e7 [2] c3 d2 [2] ed d2 [2] d2 ce }

  condition:
    any of them
}