rule TTP_XOR_WriteProcessMemory_4b81 {
  strings:
    $key_4b81 = { 1c f3 [2] 2e d1 [2] 28 e4 [2] 06 e4 [2] 39 f8 }

  condition:
    any of them
}