rule TTP_XOR_WriteProcessMemory_3996 {
  strings:
    $key_3996 = { 6e e4 [2] 5c c6 [2] 5a f3 [2] 74 f3 [2] 4b ef }

  condition:
    any of them
}