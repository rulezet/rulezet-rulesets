rule TTP_XOR_WriteProcessMemory_a7d2 {
  strings:
    $key_a7d2 = { f0 a0 [2] c2 82 [2] c4 b7 [2] ea b7 [2] d5 ab }

  condition:
    any of them
}