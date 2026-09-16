rule TTP_XOR_WriteProcessMemory_5766 {
  strings:
    $key_5766 = { 00 14 [2] 32 36 [2] 34 03 [2] 1a 03 [2] 25 1f }

  condition:
    any of them
}