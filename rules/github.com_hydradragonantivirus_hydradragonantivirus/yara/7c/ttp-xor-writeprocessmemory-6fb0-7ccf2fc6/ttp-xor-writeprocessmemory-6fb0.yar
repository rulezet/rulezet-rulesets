rule TTP_XOR_WriteProcessMemory_6fb0 {
  strings:
    $key_6fb0 = { 38 c2 [2] 0a e0 [2] 0c d5 [2] 22 d5 [2] 1d c9 }

  condition:
    any of them
}