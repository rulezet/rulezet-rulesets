rule TTP_XOR_WriteProcessMemory_1346 {
  strings:
    $key_1346 = { 44 34 [2] 76 16 [2] 70 23 [2] 5e 23 [2] 61 3f }

  condition:
    any of them
}