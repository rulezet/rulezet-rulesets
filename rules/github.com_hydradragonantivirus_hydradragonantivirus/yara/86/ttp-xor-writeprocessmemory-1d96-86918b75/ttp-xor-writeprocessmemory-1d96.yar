rule TTP_XOR_WriteProcessMemory_1d96 {
  strings:
    $key_1d96 = { 4a e4 [2] 78 c6 [2] 7e f3 [2] 50 f3 [2] 6f ef }

  condition:
    any of them
}