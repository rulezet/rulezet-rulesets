rule TTP_XOR_WriteProcessMemory_2b81 {
  strings:
    $key_2b81 = { 7c f3 [2] 4e d1 [2] 48 e4 [2] 66 e4 [2] 59 f8 }

  condition:
    any of them
}