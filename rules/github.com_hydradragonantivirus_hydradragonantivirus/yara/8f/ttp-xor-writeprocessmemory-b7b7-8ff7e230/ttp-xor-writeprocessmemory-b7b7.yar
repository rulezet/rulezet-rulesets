rule TTP_XOR_WriteProcessMemory_b7b7 {
  strings:
    $key_b7b7 = { e0 c5 [2] d2 e7 [2] d4 d2 [2] fa d2 [2] c5 ce }

  condition:
    any of them
}