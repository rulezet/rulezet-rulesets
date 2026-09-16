rule TTP_XOR_WriteProcessMemory_4e92 {
  strings:
    $key_4e92 = { 19 e0 [2] 2b c2 [2] 2d f7 [2] 03 f7 [2] 3c eb }

  condition:
    any of them
}