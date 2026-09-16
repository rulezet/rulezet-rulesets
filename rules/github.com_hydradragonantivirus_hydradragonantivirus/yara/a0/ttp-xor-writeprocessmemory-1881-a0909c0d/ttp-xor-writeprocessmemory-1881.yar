rule TTP_XOR_WriteProcessMemory_1881 {
  strings:
    $key_1881 = { 4f f3 [2] 7d d1 [2] 7b e4 [2] 55 e4 [2] 6a f8 }

  condition:
    any of them
}