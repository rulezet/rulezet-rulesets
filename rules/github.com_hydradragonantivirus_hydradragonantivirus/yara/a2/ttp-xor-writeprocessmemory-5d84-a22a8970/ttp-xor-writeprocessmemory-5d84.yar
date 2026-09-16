rule TTP_XOR_WriteProcessMemory_5d84 {
  strings:
    $key_5d84 = { 0a f6 [2] 38 d4 [2] 3e e1 [2] 10 e1 [2] 2f fd }

  condition:
    any of them
}