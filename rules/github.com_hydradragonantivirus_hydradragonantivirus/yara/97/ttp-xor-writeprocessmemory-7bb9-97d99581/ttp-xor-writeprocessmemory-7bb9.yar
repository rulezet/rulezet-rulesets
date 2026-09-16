rule TTP_XOR_WriteProcessMemory_7bb9 {
  strings:
    $key_7bb9 = { 2c cb [2] 1e e9 [2] 18 dc [2] 36 dc [2] 09 c0 }

  condition:
    any of them
}