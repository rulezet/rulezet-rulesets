rule TTP_XOR_WriteProcessMemory_4e90 {
  strings:
    $key_4e90 = { 19 e2 [2] 2b c0 [2] 2d f5 [2] 03 f5 [2] 3c e9 }

  condition:
    any of them
}