rule TTP_XOR_WriteProcessMemory_8c85 {
  strings:
    $key_8c85 = { db f7 [2] e9 d5 [2] ef e0 [2] c1 e0 [2] fe fc }

  condition:
    any of them
}