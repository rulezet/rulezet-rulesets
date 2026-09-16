rule TTP_XOR_WriteProcessMemory_4e46 {
  strings:
    $key_4e46 = { 19 34 [2] 2b 16 [2] 2d 23 [2] 03 23 [2] 3c 3f }

  condition:
    any of them
}