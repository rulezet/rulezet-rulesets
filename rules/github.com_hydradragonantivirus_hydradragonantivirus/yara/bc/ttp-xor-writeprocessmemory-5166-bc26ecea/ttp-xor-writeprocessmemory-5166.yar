rule TTP_XOR_WriteProcessMemory_5166 {
  strings:
    $key_5166 = { 06 14 [2] 34 36 [2] 32 03 [2] 1c 03 [2] 23 1f }

  condition:
    any of them
}