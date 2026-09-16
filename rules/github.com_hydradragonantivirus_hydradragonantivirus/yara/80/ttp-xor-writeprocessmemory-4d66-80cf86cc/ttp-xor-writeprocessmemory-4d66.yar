rule TTP_XOR_WriteProcessMemory_4d66 {
  strings:
    $key_4d66 = { 1a 14 [2] 28 36 [2] 2e 03 [2] 00 03 [2] 3f 1f }

  condition:
    any of them
}