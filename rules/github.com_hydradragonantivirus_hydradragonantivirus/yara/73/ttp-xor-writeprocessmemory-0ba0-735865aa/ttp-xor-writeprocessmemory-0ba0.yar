rule TTP_XOR_WriteProcessMemory_0ba0 {
  strings:
    $key_0ba0 = { 5c d2 [2] 6e f0 [2] 68 c5 [2] 46 c5 [2] 79 d9 }

  condition:
    any of them
}