rule TTP_XOR_WriteProcessMemory_4d96 {
  strings:
    $key_4d96 = { 1a e4 [2] 28 c6 [2] 2e f3 [2] 00 f3 [2] 3f ef }

  condition:
    any of them
}