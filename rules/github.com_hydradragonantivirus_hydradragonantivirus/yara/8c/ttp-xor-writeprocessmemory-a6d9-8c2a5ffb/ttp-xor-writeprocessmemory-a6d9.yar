rule TTP_XOR_WriteProcessMemory_a6d9 {
  strings:
    $key_a6d9 = { f1 ab [2] c3 89 [2] c5 bc [2] eb bc [2] d4 a0 }

  condition:
    any of them
}