rule TTP_XOR_WriteProcessMemory_1fb0 {
  strings:
    $key_1fb0 = { 48 c2 [2] 7a e0 [2] 7c d5 [2] 52 d5 [2] 6d c9 }

  condition:
    any of them
}