rule TTP_XOR_WriteProcessMemory_b7d6 {
  strings:
    $key_b7d6 = { e0 a4 [2] d2 86 [2] d4 b3 [2] fa b3 [2] c5 af }

  condition:
    any of them
}