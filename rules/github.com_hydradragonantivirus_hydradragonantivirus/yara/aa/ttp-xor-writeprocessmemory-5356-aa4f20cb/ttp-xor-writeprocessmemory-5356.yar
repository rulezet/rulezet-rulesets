rule TTP_XOR_WriteProcessMemory_5356 {
  strings:
    $key_5356 = { 04 24 [2] 36 06 [2] 30 33 [2] 1e 33 [2] 21 2f }

  condition:
    any of them
}