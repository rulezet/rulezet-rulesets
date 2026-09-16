rule TTP_XOR_WriteProcessMemory_67c1 {
  strings:
    $key_67c1 = { 30 b3 [2] 02 91 [2] 04 a4 [2] 2a a4 [2] 15 b8 }

  condition:
    any of them
}