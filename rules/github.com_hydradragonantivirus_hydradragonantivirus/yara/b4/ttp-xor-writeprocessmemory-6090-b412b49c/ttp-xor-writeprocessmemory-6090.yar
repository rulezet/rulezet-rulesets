rule TTP_XOR_WriteProcessMemory_6090 {
  strings:
    $key_6090 = { 37 e2 [2] 05 c0 [2] 03 f5 [2] 2d f5 [2] 12 e9 }

  condition:
    any of them
}