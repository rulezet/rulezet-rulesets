rule TTP_XOR_WriteProcessMemory_7ba5 {
  strings:
    $key_7ba5 = { 2c d7 [2] 1e f5 [2] 18 c0 [2] 36 c0 [2] 09 dc }

  condition:
    any of them
}