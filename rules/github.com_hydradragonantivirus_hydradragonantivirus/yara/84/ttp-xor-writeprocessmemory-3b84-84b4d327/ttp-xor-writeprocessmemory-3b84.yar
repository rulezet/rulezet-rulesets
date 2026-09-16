rule TTP_XOR_WriteProcessMemory_3b84 {
  strings:
    $key_3b84 = { 6c f6 [2] 5e d4 [2] 58 e1 [2] 76 e1 [2] 49 fd }

  condition:
    any of them
}