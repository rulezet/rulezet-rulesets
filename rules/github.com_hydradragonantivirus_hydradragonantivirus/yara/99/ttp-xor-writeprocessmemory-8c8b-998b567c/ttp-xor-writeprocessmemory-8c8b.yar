rule TTP_XOR_WriteProcessMemory_8c8b {
  strings:
    $key_8c8b = { db f9 [2] e9 db [2] ef ee [2] c1 ee [2] fe f2 }

  condition:
    any of them
}