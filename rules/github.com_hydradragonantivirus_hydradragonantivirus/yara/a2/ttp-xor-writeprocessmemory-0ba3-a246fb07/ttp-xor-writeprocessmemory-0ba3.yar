rule TTP_XOR_WriteProcessMemory_0ba3 {
  strings:
    $key_0ba3 = { 5c d1 [2] 6e f3 [2] 68 c6 [2] 46 c6 [2] 79 da }

  condition:
    any of them
}