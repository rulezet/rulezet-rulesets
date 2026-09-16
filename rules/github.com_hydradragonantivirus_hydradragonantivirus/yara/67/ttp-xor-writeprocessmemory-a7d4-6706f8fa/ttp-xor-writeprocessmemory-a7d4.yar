rule TTP_XOR_WriteProcessMemory_a7d4 {
  strings:
    $key_a7d4 = { f0 a6 [2] c2 84 [2] c4 b1 [2] ea b1 [2] d5 ad }

  condition:
    any of them
}