rule TTP_XOR_WriteProcessMemory_5e92 {
  strings:
    $key_5e92 = { 09 e0 [2] 3b c2 [2] 3d f7 [2] 13 f7 [2] 2c eb }

  condition:
    any of them
}