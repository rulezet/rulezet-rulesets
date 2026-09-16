rule TTP_XOR_WriteProcessMemory_1ae6 {
  strings:
    $key_1ae6 = { 4d 94 [2] 7f b6 [2] 79 83 [2] 57 83 [2] 68 9f }

  condition:
    any of them
}