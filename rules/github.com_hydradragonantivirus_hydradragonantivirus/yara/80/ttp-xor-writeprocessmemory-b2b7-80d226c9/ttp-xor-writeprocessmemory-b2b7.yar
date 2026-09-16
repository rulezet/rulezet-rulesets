rule TTP_XOR_WriteProcessMemory_b2b7 {
  strings:
    $key_b2b7 = { e5 c5 [2] d7 e7 [2] d1 d2 [2] ff d2 [2] c0 ce }

  condition:
    any of them
}