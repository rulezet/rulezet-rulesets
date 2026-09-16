rule TTP_XOR_WriteProcessMemory_67c0 {
  strings:
    $key_67c0 = { 30 b2 [2] 02 90 [2] 04 a5 [2] 2a a5 [2] 15 b9 }

  condition:
    any of them
}