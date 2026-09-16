rule TTP_XOR_WriteProcessMemory_78b4 {
  strings:
    $key_78b4 = { 2f c6 [2] 1d e4 [2] 1b d1 [2] 35 d1 [2] 0a cd }

  condition:
    any of them
}