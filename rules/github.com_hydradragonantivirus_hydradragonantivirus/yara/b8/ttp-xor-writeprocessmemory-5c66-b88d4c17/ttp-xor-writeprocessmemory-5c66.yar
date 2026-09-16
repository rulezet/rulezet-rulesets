rule TTP_XOR_WriteProcessMemory_5c66 {
  strings:
    $key_5c66 = { 0b 14 [2] 39 36 [2] 3f 03 [2] 11 03 [2] 2e 1f }

  condition:
    any of them
}