rule TTP_XOR_WriteProcessMemory_2d96 {
  strings:
    $key_2d96 = { 7a e4 [2] 48 c6 [2] 4e f3 [2] 60 f3 [2] 5f ef }

  condition:
    any of them
}