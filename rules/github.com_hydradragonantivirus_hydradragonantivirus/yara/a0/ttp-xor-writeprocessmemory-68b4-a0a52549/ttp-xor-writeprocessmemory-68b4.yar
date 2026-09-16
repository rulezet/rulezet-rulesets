rule TTP_XOR_WriteProcessMemory_68b4 {
  strings:
    $key_68b4 = { 3f c6 [2] 0d e4 [2] 0b d1 [2] 25 d1 [2] 1a cd }

  condition:
    any of them
}