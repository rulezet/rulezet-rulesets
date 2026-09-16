rule TTP_XOR_WriteProcessMemory_8c81 {
  strings:
    $key_8c81 = { db f3 [2] e9 d1 [2] ef e4 [2] c1 e4 [2] fe f8 }

  condition:
    any of them
}