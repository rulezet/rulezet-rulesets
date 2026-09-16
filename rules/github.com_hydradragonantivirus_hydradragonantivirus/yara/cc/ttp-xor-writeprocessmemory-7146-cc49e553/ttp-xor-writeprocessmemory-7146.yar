rule TTP_XOR_WriteProcessMemory_7146 {
  strings:
    $key_7146 = { 26 34 [2] 14 16 [2] 12 23 [2] 3c 23 [2] 03 3f }

  condition:
    any of them
}