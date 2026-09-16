rule TTP_XOR_WriteProcessMemory_7156 {
  strings:
    $key_7156 = { 26 24 [2] 14 06 [2] 12 33 [2] 3c 33 [2] 03 2f }

  condition:
    any of them
}