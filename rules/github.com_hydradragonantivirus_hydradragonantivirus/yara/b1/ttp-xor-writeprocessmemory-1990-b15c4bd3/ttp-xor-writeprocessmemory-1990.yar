rule TTP_XOR_WriteProcessMemory_1990 {
  strings:
    $key_1990 = { 4e e2 [2] 7c c0 [2] 7a f5 [2] 54 f5 [2] 6b e9 }

  condition:
    any of them
}