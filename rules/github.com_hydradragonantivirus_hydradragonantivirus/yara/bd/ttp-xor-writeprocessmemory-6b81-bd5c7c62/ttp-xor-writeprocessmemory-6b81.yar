rule TTP_XOR_WriteProcessMemory_6b81 {
  strings:
    $key_6b81 = { 3c f3 [2] 0e d1 [2] 08 e4 [2] 26 e4 [2] 19 f8 }

  condition:
    any of them
}