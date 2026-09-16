rule TTP_XOR_WriteProcessMemory_5e81 {
  strings:
    $key_5e81 = { 09 f3 [2] 3b d1 [2] 3d e4 [2] 13 e4 [2] 2c f8 }

  condition:
    any of them
}