rule TTP_XOR_WriteProcessMemory_5991 {
  strings:
    $key_5991 = { 0e e3 [2] 3c c1 [2] 3a f4 [2] 14 f4 [2] 2b e8 }

  condition:
    any of them
}