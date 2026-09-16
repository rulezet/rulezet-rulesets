rule TTP_XOR_WriteProcessMemory_feb4 {
  strings:
    $key_feb4 = { a9 c6 [2] 9b e4 [2] 9d d1 [2] b3 d1 [2] 8c cd }

  condition:
    any of them
}