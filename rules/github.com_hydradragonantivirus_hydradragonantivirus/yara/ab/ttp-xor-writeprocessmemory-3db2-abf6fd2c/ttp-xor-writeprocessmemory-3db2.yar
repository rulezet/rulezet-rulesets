rule TTP_XOR_WriteProcessMemory_3db2 {
  strings:
    $key_3db2 = { 6a c0 [2] 58 e2 [2] 5e d7 [2] 70 d7 [2] 4f cb }

  condition:
    any of them
}