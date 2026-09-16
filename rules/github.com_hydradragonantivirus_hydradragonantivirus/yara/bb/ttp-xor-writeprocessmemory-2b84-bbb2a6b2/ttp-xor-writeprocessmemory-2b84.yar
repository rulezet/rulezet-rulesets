rule TTP_XOR_WriteProcessMemory_2b84 {
  strings:
    $key_2b84 = { 7c f6 [2] 4e d4 [2] 48 e1 [2] 66 e1 [2] 59 fd }

  condition:
    any of them
}