rule TTP_XOR_WriteProcessMemory_b4b7 {
  strings:
    $key_b4b7 = { e3 c5 [2] d1 e7 [2] d7 d2 [2] f9 d2 [2] c6 ce }

  condition:
    any of them
}