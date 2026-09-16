rule TTP_XOR_WriteProcessMemory_b7a7 {
  strings:
    $key_b7a7 = { e0 d5 [2] d2 f7 [2] d4 c2 [2] fa c2 [2] c5 de }

  condition:
    any of them
}