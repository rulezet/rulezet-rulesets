rule TTP_XOR_WriteProcessMemory_a4f0 {
  strings:
    $key_a4f0 = { f3 82 [2] c1 a0 [2] c7 95 [2] e9 95 [2] d6 89 }

  condition:
    any of them
}