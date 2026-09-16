rule TTP_XOR_WriteProcessMemory_1991 {
  strings:
    $key_1991 = { 4e e3 [2] 7c c1 [2] 7a f4 [2] 54 f4 [2] 6b e8 }

  condition:
    any of them
}