rule TTP_XOR_WriteProcessMemory_7246 {
  strings:
    $key_7246 = { 25 34 [2] 17 16 [2] 11 23 [2] 3f 23 [2] 00 3f }

  condition:
    any of them
}