rule TTP_XOR_WriteProcessMemory_4ae6 {
  strings:
    $key_4ae6 = { 1d 94 [2] 2f b6 [2] 29 83 [2] 07 83 [2] 38 9f }

  condition:
    any of them
}