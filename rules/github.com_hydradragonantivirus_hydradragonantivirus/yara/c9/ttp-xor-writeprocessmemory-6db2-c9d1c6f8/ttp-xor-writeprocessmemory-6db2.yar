rule TTP_XOR_WriteProcessMemory_6db2 {
  strings:
    $key_6db2 = { 3a c0 [2] 08 e2 [2] 0e d7 [2] 20 d7 [2] 1f cb }

  condition:
    any of them
}