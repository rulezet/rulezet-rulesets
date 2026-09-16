rule TTP_XOR_WriteProcessMemory_2eb4 {
  strings:
    $key_2eb4 = { 79 c6 [2] 4b e4 [2] 4d d1 [2] 63 d1 [2] 5c cd }

  condition:
    any of them
}