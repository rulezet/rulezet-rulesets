rule TTP_XOR_WriteProcessMemory_7bb4 {
  strings:
    $key_7bb4 = { 2c c6 [2] 1e e4 [2] 18 d1 [2] 36 d1 [2] 09 cd }

  condition:
    any of them
}