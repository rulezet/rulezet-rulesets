rule TTP_XOR_WriteProcessMemory_5e80 {
  strings:
    $key_5e80 = { 09 f2 [2] 3b d0 [2] 3d e5 [2] 13 e5 [2] 2c f9 }

  condition:
    any of them
}