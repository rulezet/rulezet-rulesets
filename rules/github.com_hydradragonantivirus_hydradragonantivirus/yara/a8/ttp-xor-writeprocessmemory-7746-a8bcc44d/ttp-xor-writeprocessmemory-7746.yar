rule TTP_XOR_WriteProcessMemory_7746 {
  strings:
    $key_7746 = { 20 34 [2] 12 16 [2] 14 23 [2] 3a 23 [2] 05 3f }

  condition:
    any of them
}