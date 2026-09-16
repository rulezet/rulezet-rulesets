rule TTP_XOR_WriteProcessMemory_7db4 {
  strings:
    $key_7db4 = { 2a c6 [2] 18 e4 [2] 1e d1 [2] 30 d1 [2] 0f cd }

  condition:
    any of them
}