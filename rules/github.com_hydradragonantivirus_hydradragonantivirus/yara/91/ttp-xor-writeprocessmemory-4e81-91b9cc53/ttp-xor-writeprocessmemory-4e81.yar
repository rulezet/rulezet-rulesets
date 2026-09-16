rule TTP_XOR_WriteProcessMemory_4e81 {
  strings:
    $key_4e81 = { 19 f3 [2] 2b d1 [2] 2d e4 [2] 03 e4 [2] 3c f8 }

  condition:
    any of them
}