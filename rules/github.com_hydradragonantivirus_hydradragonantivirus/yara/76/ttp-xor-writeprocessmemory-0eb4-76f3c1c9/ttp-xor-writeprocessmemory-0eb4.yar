rule TTP_XOR_WriteProcessMemory_0eb4 {
  strings:
    $key_0eb4 = { 59 c6 [2] 6b e4 [2] 6d d1 [2] 43 d1 [2] 7c cd }

  condition:
    any of them
}