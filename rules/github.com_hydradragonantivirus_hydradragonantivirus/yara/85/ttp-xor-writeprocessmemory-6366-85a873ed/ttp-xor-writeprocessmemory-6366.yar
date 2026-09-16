rule TTP_XOR_WriteProcessMemory_6366 {
  strings:
    $key_6366 = { 34 14 [2] 06 36 [2] 00 03 [2] 2e 03 [2] 11 1f }

  condition:
    any of them
}