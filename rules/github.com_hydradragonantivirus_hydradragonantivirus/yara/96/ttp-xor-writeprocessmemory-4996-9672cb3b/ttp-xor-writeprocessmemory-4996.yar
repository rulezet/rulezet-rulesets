rule TTP_XOR_WriteProcessMemory_4996 {
  strings:
    $key_4996 = { 1e e4 [2] 2c c6 [2] 2a f3 [2] 04 f3 [2] 3b ef }

  condition:
    any of them
}