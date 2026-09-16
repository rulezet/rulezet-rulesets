rule TTP_XOR_WriteProcessMemory_56c1 {
  strings:
    $key_56c1 = { 01 b3 [2] 33 91 [2] 35 a4 [2] 1b a4 [2] 24 b8 }

  condition:
    any of them
}