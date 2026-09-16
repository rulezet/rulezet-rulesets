rule TTP_XOR_WriteProcessMemory_6996 {
  strings:
    $key_6996 = { 3e e4 [2] 0c c6 [2] 0a f3 [2] 24 f3 [2] 1b ef }

  condition:
    any of them
}