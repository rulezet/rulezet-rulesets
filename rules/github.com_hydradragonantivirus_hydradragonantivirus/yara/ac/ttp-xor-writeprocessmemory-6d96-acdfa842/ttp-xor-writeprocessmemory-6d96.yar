rule TTP_XOR_WriteProcessMemory_6d96 {
  strings:
    $key_6d96 = { 3a e4 [2] 08 c6 [2] 0e f3 [2] 20 f3 [2] 1f ef }

  condition:
    any of them
}