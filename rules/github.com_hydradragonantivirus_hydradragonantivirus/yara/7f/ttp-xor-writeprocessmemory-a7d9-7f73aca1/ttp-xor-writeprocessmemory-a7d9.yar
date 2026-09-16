rule TTP_XOR_WriteProcessMemory_a7d9 {
  strings:
    $key_a7d9 = { f0 ab [2] c2 89 [2] c4 bc [2] ea bc [2] d5 a0 }

  condition:
    any of them
}