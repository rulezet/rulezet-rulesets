rule TTP_XOR_WriteProcessMemory_1a84 {
  strings:
    $key_1a84 = { 4d f6 [2] 7f d4 [2] 79 e1 [2] 57 e1 [2] 68 fd }

  condition:
    any of them
}