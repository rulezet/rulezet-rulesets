rule TTP_XOR_WriteProcessMemory_4fb4 {
  strings:
    $key_4fb4 = { 18 c6 [2] 2a e4 [2] 2c d1 [2] 02 d1 [2] 3d cd }

  condition:
    any of them
}