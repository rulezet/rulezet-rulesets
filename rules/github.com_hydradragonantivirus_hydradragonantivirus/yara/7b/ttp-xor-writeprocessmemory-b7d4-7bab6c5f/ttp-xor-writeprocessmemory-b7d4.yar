rule TTP_XOR_WriteProcessMemory_b7d4 {
  strings:
    $key_b7d4 = { e0 a6 [2] d2 84 [2] d4 b1 [2] fa b1 [2] c5 ad }

  condition:
    any of them
}