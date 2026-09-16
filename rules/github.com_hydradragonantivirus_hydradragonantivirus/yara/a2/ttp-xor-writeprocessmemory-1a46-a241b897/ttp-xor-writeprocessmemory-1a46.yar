rule TTP_XOR_WriteProcessMemory_1a46 {
  strings:
    $key_1a46 = { 4d 34 [2] 7f 16 [2] 79 23 [2] 57 23 [2] 68 3f }

  condition:
    any of them
}