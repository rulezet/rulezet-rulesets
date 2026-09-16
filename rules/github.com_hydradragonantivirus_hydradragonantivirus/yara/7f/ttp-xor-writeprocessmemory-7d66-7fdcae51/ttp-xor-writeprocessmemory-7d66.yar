rule TTP_XOR_WriteProcessMemory_7d66 {
  strings:
    $key_7d66 = { 2a 14 [2] 18 36 [2] 1e 03 [2] 30 03 [2] 0f 1f }

  condition:
    any of them
}