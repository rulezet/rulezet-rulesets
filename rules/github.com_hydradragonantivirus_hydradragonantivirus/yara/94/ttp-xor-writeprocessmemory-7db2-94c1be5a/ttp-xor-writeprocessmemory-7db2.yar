rule TTP_XOR_WriteProcessMemory_7db2 {
  strings:
    $key_7db2 = { 2a c0 [2] 18 e2 [2] 1e d7 [2] 30 d7 [2] 0f cb }

  condition:
    any of them
}