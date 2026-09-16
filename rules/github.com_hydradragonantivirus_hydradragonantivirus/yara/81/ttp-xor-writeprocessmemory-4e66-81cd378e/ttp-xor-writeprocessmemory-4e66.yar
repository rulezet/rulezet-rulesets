rule TTP_XOR_WriteProcessMemory_4e66 {
  strings:
    $key_4e66 = { 19 14 [2] 2b 36 [2] 2d 03 [2] 03 03 [2] 3c 1f }

  condition:
    any of them
}