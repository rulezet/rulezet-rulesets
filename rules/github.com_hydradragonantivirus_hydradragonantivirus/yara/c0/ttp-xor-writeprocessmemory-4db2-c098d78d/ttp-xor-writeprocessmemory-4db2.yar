rule TTP_XOR_WriteProcessMemory_4db2 {
  strings:
    $key_4db2 = { 1a c0 [2] 28 e2 [2] 2e d7 [2] 00 d7 [2] 3f cb }

  condition:
    any of them
}