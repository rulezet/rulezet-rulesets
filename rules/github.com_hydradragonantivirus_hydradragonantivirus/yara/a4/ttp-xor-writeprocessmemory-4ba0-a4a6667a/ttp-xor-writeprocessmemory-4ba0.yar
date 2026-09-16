rule TTP_XOR_WriteProcessMemory_4ba0 {
  strings:
    $key_4ba0 = { 1c d2 [2] 2e f0 [2] 28 c5 [2] 06 c5 [2] 39 d9 }

  condition:
    any of them
}