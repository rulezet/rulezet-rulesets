rule TTP_XOR_WriteProcessMemory_6fb1 {
  strings:
    $key_6fb1 = { 38 c3 [2] 0a e1 [2] 0c d4 [2] 22 d4 [2] 1d c8 }

  condition:
    any of them
}