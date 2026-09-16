rule TTP_XOR_WriteProcessMemory_4bd1 {
  strings:
    $key_4bd1 = { 1c a3 [2] 2e 81 [2] 28 b4 [2] 06 b4 [2] 39 a8 }

  condition:
    any of them
}