rule TTP_XOR_WriteProcessMemory_0881 {
  strings:
    $key_0881 = { 5f f3 [2] 6d d1 [2] 6b e4 [2] 45 e4 [2] 7a f8 }

  condition:
    any of them
}