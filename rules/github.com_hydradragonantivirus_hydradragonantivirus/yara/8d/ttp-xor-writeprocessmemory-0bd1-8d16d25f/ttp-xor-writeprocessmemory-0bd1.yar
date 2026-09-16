rule TTP_XOR_WriteProcessMemory_0bd1 {
  strings:
    $key_0bd1 = { 5c a3 [2] 6e 81 [2] 68 b4 [2] 46 b4 [2] 79 a8 }

  condition:
    any of them
}