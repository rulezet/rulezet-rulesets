rule TTP_XOR_WriteProcessMemory_5646 {
  strings:
    $key_5646 = { 01 34 [2] 33 16 [2] 35 23 [2] 1b 23 [2] 24 3f }

  condition:
    any of them
}