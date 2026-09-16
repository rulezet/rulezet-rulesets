rule TTP_XOR_WriteProcessMemory_5a46 {
  strings:
    $key_5a46 = { 0d 34 [2] 3f 16 [2] 39 23 [2] 17 23 [2] 28 3f }

  condition:
    any of them
}