rule TTP_XOR_WriteProcessMemory_e990 {
  strings:
    $key_e990 = { be e2 [2] 8c c0 [2] 8a f5 [2] a4 f5 [2] 9b e9 }

  condition:
    any of them
}