rule TTP_XOR_WriteProcessMemory_b7a4 {
  strings:
    $key_b7a4 = { e0 d6 [2] d2 f4 [2] d4 c1 [2] fa c1 [2] c5 dd }

  condition:
    any of them
}