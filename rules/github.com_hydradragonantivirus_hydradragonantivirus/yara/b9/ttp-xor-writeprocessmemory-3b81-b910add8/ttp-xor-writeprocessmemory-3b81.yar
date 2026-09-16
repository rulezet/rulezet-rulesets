rule TTP_XOR_WriteProcessMemory_3b81 {
  strings:
    $key_3b81 = { 6c f3 [2] 5e d1 [2] 58 e4 [2] 76 e4 [2] 49 f8 }

  condition:
    any of them
}