rule TTP_XOR_WriteProcessMemory_4eb4 {
  strings:
    $key_4eb4 = { 19 c6 [2] 2b e4 [2] 2d d1 [2] 03 d1 [2] 3c cd }

  condition:
    any of them
}