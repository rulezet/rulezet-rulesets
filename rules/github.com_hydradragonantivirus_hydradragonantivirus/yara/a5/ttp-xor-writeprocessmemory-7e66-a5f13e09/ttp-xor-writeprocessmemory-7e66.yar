rule TTP_XOR_WriteProcessMemory_7e66 {
  strings:
    $key_7e66 = { 29 14 [2] 1b 36 [2] 1d 03 [2] 33 03 [2] 0c 1f }

  condition:
    any of them
}