rule TTP_XOR_WriteProcessMemory_b1b7 {
  strings:
    $key_b1b7 = { e6 c5 [2] d4 e7 [2] d2 d2 [2] fc d2 [2] c3 ce }

  condition:
    any of them
}