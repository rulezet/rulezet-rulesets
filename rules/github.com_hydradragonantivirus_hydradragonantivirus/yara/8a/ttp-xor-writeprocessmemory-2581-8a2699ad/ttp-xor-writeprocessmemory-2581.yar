rule TTP_XOR_WriteProcessMemory_2581 {
  strings:
    $key_2581 = { 72 f3 [2] 40 d1 [2] 46 e4 [2] 68 e4 [2] 57 f8 }

  condition:
    any of them
}