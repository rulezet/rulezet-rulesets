rule TTP_XOR_WriteProcessMemory_5d96 {
  strings:
    $key_5d96 = { 0a e4 [2] 38 c6 [2] 3e f3 [2] 10 f3 [2] 2f ef }

  condition:
    any of them
}