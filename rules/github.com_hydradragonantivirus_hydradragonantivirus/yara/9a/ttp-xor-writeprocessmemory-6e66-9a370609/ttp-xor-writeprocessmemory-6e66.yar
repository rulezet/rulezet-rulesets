rule TTP_XOR_WriteProcessMemory_6e66 {
  strings:
    $key_6e66 = { 39 14 [2] 0b 36 [2] 0d 03 [2] 23 03 [2] 1c 1f }

  condition:
    any of them
}