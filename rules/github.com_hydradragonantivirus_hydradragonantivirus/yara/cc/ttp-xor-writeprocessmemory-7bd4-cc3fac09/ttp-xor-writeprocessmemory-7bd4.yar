rule TTP_XOR_WriteProcessMemory_7bd4 {
  strings:
    $key_7bd4 = { 2c a6 [2] 1e 84 [2] 18 b1 [2] 36 b1 [2] 09 ad }

  condition:
    any of them
}