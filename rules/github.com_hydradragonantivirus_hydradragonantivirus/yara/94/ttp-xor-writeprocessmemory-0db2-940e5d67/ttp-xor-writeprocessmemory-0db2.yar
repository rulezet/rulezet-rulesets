rule TTP_XOR_WriteProcessMemory_0db2 {
  strings:
    $key_0db2 = { 5a c0 [2] 68 e2 [2] 6e d7 [2] 40 d7 [2] 7f cb }

  condition:
    any of them
}