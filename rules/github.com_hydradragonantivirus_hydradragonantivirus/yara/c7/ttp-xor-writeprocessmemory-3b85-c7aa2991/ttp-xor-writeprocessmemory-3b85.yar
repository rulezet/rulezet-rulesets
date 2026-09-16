rule TTP_XOR_WriteProcessMemory_3b85 {
  strings:
    $key_3b85 = { 6c f7 [2] 5e d5 [2] 58 e0 [2] 76 e0 [2] 49 fc }

  condition:
    any of them
}