rule TTP_XOR_WriteProcessMemory_4991 {
  strings:
    $key_4991 = { 1e e3 [2] 2c c1 [2] 2a f4 [2] 04 f4 [2] 3b e8 }

  condition:
    any of them
}