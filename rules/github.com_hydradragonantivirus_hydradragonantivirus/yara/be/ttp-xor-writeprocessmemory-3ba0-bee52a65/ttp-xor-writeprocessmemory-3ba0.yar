rule TTP_XOR_WriteProcessMemory_3ba0 {
  strings:
    $key_3ba0 = { 6c d2 [2] 5e f0 [2] 58 c5 [2] 76 c5 [2] 49 d9 }

  condition:
    any of them
}