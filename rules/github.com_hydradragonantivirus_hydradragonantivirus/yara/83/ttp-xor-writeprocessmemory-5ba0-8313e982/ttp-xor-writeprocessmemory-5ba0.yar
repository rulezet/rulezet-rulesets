rule TTP_XOR_WriteProcessMemory_5ba0 {
  strings:
    $key_5ba0 = { 0c d2 [2] 3e f0 [2] 38 c5 [2] 16 c5 [2] 29 d9 }

  condition:
    any of them
}