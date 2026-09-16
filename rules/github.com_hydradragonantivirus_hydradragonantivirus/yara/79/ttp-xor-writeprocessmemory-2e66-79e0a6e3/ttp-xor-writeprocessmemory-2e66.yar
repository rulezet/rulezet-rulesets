rule TTP_XOR_WriteProcessMemory_2e66 {
  strings:
    $key_2e66 = { 79 14 [2] 4b 36 [2] 4d 03 [2] 63 03 [2] 5c 1f }

  condition:
    any of them
}