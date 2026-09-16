rule TTP_XOR_WriteProcessMemory_5b85 {
  strings:
    $key_5b85 = { 0c f7 [2] 3e d5 [2] 38 e0 [2] 16 e0 [2] 29 fc }

  condition:
    any of them
}