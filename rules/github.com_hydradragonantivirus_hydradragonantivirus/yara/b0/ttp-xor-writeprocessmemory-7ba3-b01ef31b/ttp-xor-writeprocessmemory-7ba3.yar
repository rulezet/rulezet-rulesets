rule TTP_XOR_WriteProcessMemory_7ba3 {
  strings:
    $key_7ba3 = { 2c d1 [2] 1e f3 [2] 18 c6 [2] 36 c6 [2] 09 da }

  condition:
    any of them
}