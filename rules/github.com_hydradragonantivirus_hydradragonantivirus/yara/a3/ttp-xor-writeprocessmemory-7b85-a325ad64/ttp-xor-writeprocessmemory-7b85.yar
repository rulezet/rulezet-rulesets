rule TTP_XOR_WriteProcessMemory_7b85 {
  strings:
    $key_7b85 = { 2c f7 [2] 1e d5 [2] 18 e0 [2] 36 e0 [2] 09 fc }

  condition:
    any of them
}