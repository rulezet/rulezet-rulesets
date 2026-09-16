rule TTP_XOR_WriteProcessMemory_fb84 {
  strings:
    $key_fb84 = { ac f6 [2] 9e d4 [2] 98 e1 [2] b6 e1 [2] 89 fd }

  condition:
    any of them
}