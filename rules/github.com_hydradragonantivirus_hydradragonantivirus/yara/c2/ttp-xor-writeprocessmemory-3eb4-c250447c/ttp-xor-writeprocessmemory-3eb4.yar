rule TTP_XOR_WriteProcessMemory_3eb4 {
  strings:
    $key_3eb4 = { 69 c6 [2] 5b e4 [2] 5d d1 [2] 73 d1 [2] 4c cd }

  condition:
    any of them
}