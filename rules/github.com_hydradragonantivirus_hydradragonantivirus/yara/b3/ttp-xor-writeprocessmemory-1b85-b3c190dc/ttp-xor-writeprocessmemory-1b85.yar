rule TTP_XOR_WriteProcessMemory_1b85 {
  strings:
    $key_1b85 = { 4c f7 [2] 7e d5 [2] 78 e0 [2] 56 e0 [2] 69 fc }

  condition:
    any of them
}