rule TTP_XOR_WriteProcessMemory_7d96 {
  strings:
    $key_7d96 = { 2a e4 [2] 18 c6 [2] 1e f3 [2] 30 f3 [2] 0f ef }

  condition:
    any of them
}