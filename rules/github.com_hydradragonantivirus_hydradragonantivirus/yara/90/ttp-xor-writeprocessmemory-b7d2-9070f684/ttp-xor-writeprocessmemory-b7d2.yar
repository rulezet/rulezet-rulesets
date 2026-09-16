rule TTP_XOR_WriteProcessMemory_b7d2 {
  strings:
    $key_b7d2 = { e0 a0 [2] d2 82 [2] d4 b7 [2] fa b7 [2] c5 ab }

  condition:
    any of them
}