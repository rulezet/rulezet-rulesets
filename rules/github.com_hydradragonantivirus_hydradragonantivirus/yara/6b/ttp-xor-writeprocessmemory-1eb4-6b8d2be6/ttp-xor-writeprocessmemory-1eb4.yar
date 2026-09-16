rule TTP_XOR_WriteProcessMemory_1eb4 {
  strings:
    $key_1eb4 = { 49 c6 [2] 7b e4 [2] 7d d1 [2] 53 d1 [2] 6c cd }

  condition:
    any of them
}