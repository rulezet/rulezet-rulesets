rule TTP_XOR_WriteProcessMemory_6556 {
  strings:
    $key_6556 = { 32 24 [2] 00 06 [2] 06 33 [2] 28 33 [2] 17 2f }

  condition:
    any of them
}