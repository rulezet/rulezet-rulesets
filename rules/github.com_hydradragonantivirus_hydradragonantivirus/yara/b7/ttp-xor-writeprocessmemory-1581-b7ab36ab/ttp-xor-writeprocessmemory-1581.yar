rule TTP_XOR_WriteProcessMemory_1581 {
  strings:
    $key_1581 = { 42 f3 [2] 70 d1 [2] 76 e4 [2] 58 e4 [2] 67 f8 }

  condition:
    any of them
}