rule TTP_XOR_WriteProcessMemory_7996 {
  strings:
    $key_7996 = { 2e e4 [2] 1c c6 [2] 1a f3 [2] 34 f3 [2] 0b ef }

  condition:
    any of them
}