rule TTP_XOR_WriteProcessMemory_7bb0 {
  strings:
    $key_7bb0 = { 2c c2 [2] 1e e0 [2] 18 d5 [2] 36 d5 [2] 09 c9 }

  condition:
    any of them
}