rule TTP_XOR_WriteProcessMemory_0991 {
  strings:
    $key_0991 = { 5e e3 [2] 6c c1 [2] 6a f4 [2] 44 f4 [2] 7b e8 }

  condition:
    any of them
}