rule TTP_XOR_WriteProcessMemory_6fb4 {
  strings:
    $key_6fb4 = { 38 c6 [2] 0a e4 [2] 0c d1 [2] 22 d1 [2] 1d cd }

  condition:
    any of them
}