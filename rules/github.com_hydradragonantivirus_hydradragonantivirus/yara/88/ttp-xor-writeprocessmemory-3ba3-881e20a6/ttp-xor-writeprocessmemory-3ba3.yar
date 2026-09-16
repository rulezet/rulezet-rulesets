rule TTP_XOR_WriteProcessMemory_3ba3 {
  strings:
    $key_3ba3 = { 6c d1 [2] 5e f3 [2] 58 c6 [2] 76 c6 [2] 49 da }

  condition:
    any of them
}