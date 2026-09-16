rule TTP_XOR_WriteProcessMemory_0990 {
  strings:
    $key_0990 = { 5e e2 [2] 6c c0 [2] 6a f5 [2] 44 f5 [2] 7b e9 }

  condition:
    any of them
}