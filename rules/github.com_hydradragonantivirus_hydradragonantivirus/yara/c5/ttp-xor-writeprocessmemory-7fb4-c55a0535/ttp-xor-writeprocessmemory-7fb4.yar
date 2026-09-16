rule TTP_XOR_WriteProcessMemory_7fb4 {
  strings:
    $key_7fb4 = { 28 c6 [2] 1a e4 [2] 1c d1 [2] 32 d1 [2] 0d cd }

  condition:
    any of them
}