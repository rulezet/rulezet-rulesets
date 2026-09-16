rule TTP_XOR_WriteProcessMemory_6b84 {
  strings:
    $key_6b84 = { 3c f6 [2] 0e d4 [2] 08 e1 [2] 26 e1 [2] 19 fd }

  condition:
    any of them
}