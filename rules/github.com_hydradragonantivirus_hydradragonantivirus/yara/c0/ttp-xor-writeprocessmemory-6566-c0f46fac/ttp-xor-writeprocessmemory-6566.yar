rule TTP_XOR_WriteProcessMemory_6566 {
  strings:
    $key_6566 = { 32 14 [2] 00 36 [2] 06 03 [2] 28 03 [2] 17 1f }

  condition:
    any of them
}